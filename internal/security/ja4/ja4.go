// Package ja4 computes JA4 TLS client fingerprints (FoxIO's successor to
// JA3, https://github.com/FoxIO-LLC/ja4) from tls.ClientHelloInfo and stores
// them in a per-connection sync.Map so the HTTP handler can retrieve them
// after the handshake completes — same lifecycle as the ja3 package.
//
// Unlike JA3, JA4 sorts cipher suites and extensions before hashing, so
// clients that shuffle their handshake ordering per connection (a common
// scraper evasion tactic) still produce a stable fingerprint. The modular
// a_b_c output also keeps the human-readable "a" section comparable even
// when the hashed "b"/"c" sections drift.
package ja4

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// GREASE values (RFC 8701) are filtered from cipher suites, extensions,
// versions and signature algorithms before counting/hashing, per the JA4 spec.
var greaseSet = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

const (
	extServerName = 0x0000 // SNI — excluded from the section-c hash, still counted in section a
	extALPN       = 0x0010 // ALPN — excluded from the section-c hash, still counted in section a
	emptyHash     = "000000000000"
)

// connStore maps "host:port" → JA4 fingerprint, populated by
// tls.Config.GetConfigForClient during the TLS handshake.
var connStore sync.Map

// Store saves the JA4 fingerprint computed for a given remote address.
func Store(remoteAddr, fp string) { connStore.Store(remoteAddr, fp) }

// Get returns the stored JA4 fingerprint for remoteAddr, or "" if not found.
func Get(remoteAddr string) string {
	v, ok := connStore.Load(remoteAddr)
	if !ok {
		return ""
	}
	return v.(string)
}

// Delete removes the stored fingerprint for remoteAddr. Call when the TLS
// connection closes so connStore stays bounded by active connections.
func Delete(remoteAddr string) {
	connStore.Delete(remoteAddr)
}

// Compute derives a JA4 fingerprint ("a_b_c" format, e.g.
// "t13d1516h2_8daaf6152771_02713d6af862") from a TLS ClientHello.
func Compute(hello *tls.ClientHelloInfo) string {
	return sectionA(hello) + "_" + sectionB(hello) + "_" + sectionC(hello)
}

// sectionA is the human-readable part: transport, TLS version, SNI presence,
// cipher count, extension count, and first ALPN value's first+last character.
func sectionA(hello *tls.ClientHelloInfo) string {
	version := "00"
	var maxVer uint16
	for _, v := range hello.SupportedVersions {
		if !greaseSet[v] && v > maxVer {
			maxVer = v
		}
	}
	switch maxVer {
	case tls.VersionTLS13:
		version = "13"
	case tls.VersionTLS12:
		version = "12"
	case tls.VersionTLS11:
		version = "11"
	case tls.VersionTLS10:
		version = "10"
	case 0x0300: // SSLv3 (tls.VersionSSL30, deprecated const)
		version = "s3"
	}

	sni := "i" // no SNI: client connected by IP
	if hello.ServerName != "" {
		sni = "d" // SNI present: client connected to a domain
	}

	// This proxy only terminates TLS over TCP; "q" (QUIC) would apply if an
	// HTTP/3 listener is ever added.
	return fmt.Sprintf("t%s%s%02d%02d%s",
		version, sni,
		min(len(noGREASE(hello.CipherSuites)), 99),
		min(len(noGREASE(hello.Extensions)), 99),
		alpnChars(hello.SupportedProtos),
	)
}

// sectionB is the truncated SHA-256 of the sorted cipher suite list.
func sectionB(hello *tls.ClientHelloInfo) string {
	ciphers := noGREASE(hello.CipherSuites)
	if len(ciphers) == 0 {
		return emptyHash
	}
	slices.Sort(ciphers)
	return hash12(hexJoin(ciphers))
}

// sectionC is the truncated SHA-256 of the sorted extension list (minus SNI
// and ALPN) plus the signature algorithms in their original wire order.
func sectionC(hello *tls.ClientHelloInfo) string {
	exts := make([]uint16, 0, len(hello.Extensions))
	for _, e := range hello.Extensions {
		if greaseSet[e] || e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return emptyHash
	}
	slices.Sort(exts)

	input := hexJoin(exts)
	sigAlgs := make([]uint16, 0, len(hello.SignatureSchemes))
	for _, s := range hello.SignatureSchemes {
		if !greaseSet[uint16(s)] {
			sigAlgs = append(sigAlgs, uint16(s))
		}
	}
	if len(sigAlgs) > 0 {
		input += "_" + hexJoin(sigAlgs)
	}
	return hash12(input)
}

// alpnChars returns the first and last character of the first ALPN protocol,
// "00" when the client offered none. Non-alphanumeric first/last bytes fall
// back to the first and last characters of the value's hex encoding, per spec.
func alpnChars(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]
	if !isAlnum(first) || !isAlnum(last) {
		h := hex.EncodeToString([]byte(p))
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func noGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !greaseSet[v] {
			out = append(out, v)
		}
	}
	return out
}

// hexJoin renders values as comma-separated lowercase 4-digit hex ("1301,1302").
func hexJoin(vals []uint16) string {
	var sb strings.Builder
	for i, v := range vals {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%04x", v)
	}
	return sb.String()
}

// hash12 returns the first 12 hex characters of SHA-256(s).
func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
