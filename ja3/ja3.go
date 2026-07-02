// Package ja3 computes JA3 TLS fingerprints from tls.ClientHelloInfo and
// stores them in a per-connection sync.Map so the HTTP handler can retrieve
// them after the handshake is complete.
//
// Deprecated: JA3 is superseded by the ja4 package. Its MD5 hash is trivially
// evaded by clients that shuffle cipher/extension order per connection, which
// JA4 defeats by sorting before hashing. JA3 is still computed and logged
// (ja3_hash column, "legacy" in the UI) only for continuity with existing log
// data and external JA3-keyed threat feeds — do not build new detection logic
// on it. Remove this package once historical JA3 data is no longer needed.
package ja3

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// GREASE values (RFC 8701) are filtered from cipher suites and extension lists
// before hashing so that Chrome's randomised GREASE padding doesn't affect the
// fingerprint.
var greaseSet = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// connStore maps "host:port" → JA3 hash, populated by tls.Config.GetConfigForClient
// during the TLS handshake before the HTTP handler runs.
var connStore sync.Map

// Store saves the JA3 hash computed for a given remote address. Called from
// tls.Config.GetConfigForClient in main.go.
func Store(remoteAddr, hash string) { connStore.Store(remoteAddr, hash) }

// Get returns the stored JA3 hash for remoteAddr, or "" if not found.
// remoteAddr should be r.RemoteAddr ("host:port") from the HTTP request.
func Get(remoteAddr string) string {
	v, ok := connStore.Load(remoteAddr)
	if !ok {
		return ""
	}
	return v.(string)
}

// Delete removes the stored JA3 hash for remoteAddr. Call this when the TLS
// connection is closed so connStore stays bounded by active connections.
func Delete(remoteAddr string) {
	connStore.Delete(remoteAddr)
}

// Compute derives a JA3 fingerprint from a TLS ClientHello and returns the
// MD5 hex digest. The format follows the original JA3 spec:
// MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
func Compute(hello *tls.ClientHelloInfo) string {
	// All TLS 1.2+ clients set the legacy ClientHello version field to 771
	// (0x0303) for backward compatibility; TLS 1.3 capability is advertised
	// via the supported_versions extension, not this field.
	const legacyVersion = 771

	ciphers := noGREASE(hello.CipherSuites)
	exts := noGREASE(hello.Extensions) // tls.ClientHelloInfo.Extensions added Go 1.17

	curves := make([]uint16, 0, len(hello.SupportedCurves))
	for _, c := range hello.SupportedCurves {
		if !greaseSet[uint16(c)] {
			curves = append(curves, uint16(c))
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d,", legacyVersion)
	joinU16(&sb, ciphers)
	sb.WriteByte(',')
	joinU16(&sb, exts)
	sb.WriteByte(',')
	joinU16(&sb, curves)
	sb.WriteByte(',')
	joinU8(&sb, hello.SupportedPoints)

	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
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

func joinU16(sb *strings.Builder, vals []uint16) {
	for i, v := range vals {
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(sb, "%d", v)
	}
}

func joinU8(sb *strings.Builder, vals []uint8) {
	for i, v := range vals {
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(sb, "%d", v)
	}
}
