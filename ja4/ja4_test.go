package ja4

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"
)

// sha12 computes the expected truncated hash independently of the package's
// own helpers, so the tests validate ordering/filtering/formatting choices.
func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// chromeLikeHello models a TLS 1.3 browser hello: GREASE in every list, SNI,
// ALPN h2, extensions presented in arbitrary wire order.
func chromeLikeHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        "example.com",
		SupportedVersions: []uint16{0x2a2a, tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      []uint16{0x5a5a, 0x1302, 0x1301, 0x1303},
		Extensions:        []uint16{0xfafa, 0x0000, 0x0017, 0x002b, 0x0010, 0x000d, 0x0033},
		SignatureSchemes:  []tls.SignatureScheme{0x0403, 0x0804, 0x0401},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
}

func TestComputeKnownValue(t *testing.T) {
	got := Compute(chromeLikeHello())

	// a: TCP + TLS1.3 + SNI + 3 ciphers + 6 extensions (GREASE dropped,
	// SNI/ALPN still counted) + ALPN "h2" → first 'h', last '2'.
	wantA := "t13d0306h2"
	// b: ciphers sorted ascending, GREASE dropped.
	wantB := sha12("1301,1302,1303")
	// c: extensions sorted with GREASE/SNI(0000)/ALPN(0010) dropped, then
	// "_" + signature algorithms in original order.
	wantC := sha12("000d,0017,002b,0033_0403,0804,0401")

	want := wantA + "_" + wantB + "_" + wantC
	if got != want {
		t.Fatalf("Compute() = %q, want %q", got, want)
	}
}

func TestComputeStableUnderReordering(t *testing.T) {
	base := Compute(chromeLikeHello())

	shuffled := chromeLikeHello()
	shuffled.CipherSuites = []uint16{0x1303, 0x1301, 0x5a5a, 0x1302}
	shuffled.Extensions = []uint16{0x0033, 0x0010, 0x000d, 0x0000, 0xfafa, 0x002b, 0x0017}

	if got := Compute(shuffled); got != base {
		t.Fatalf("reordered hello produced %q, want %q — JA4 must be order-invariant", got, base)
	}
}

func TestComputeSectionA(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*tls.ClientHelloInfo)
		wantA  string
	}{
		{"no SNI means i", func(h *tls.ClientHelloInfo) { h.ServerName = "" }, "t13i0306h2"},
		{"tls12 client", func(h *tls.ClientHelloInfo) {
			h.SupportedVersions = []uint16{tls.VersionTLS12, tls.VersionTLS11}
		}, "t12d0306h2"},
		{"no ALPN means 00", func(h *tls.ClientHelloInfo) { h.SupportedProtos = nil }, "t13d030600"},
		{"http/1.1 ALPN", func(h *tls.ClientHelloInfo) { h.SupportedProtos = []string{"http/1.1"} }, "t13d0306h1"},
		{"non-alnum ALPN falls back to hex", func(h *tls.ClientHelloInfo) {
			h.SupportedProtos = []string{"\x01\x02"} // hex "0102" → first '0', last '2'
		}, "t13d030602"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := chromeLikeHello()
			tc.mutate(h)
			gotA := strings.SplitN(Compute(h), "_", 2)[0]
			if gotA != tc.wantA {
				t.Errorf("section a = %q, want %q", gotA, tc.wantA)
			}
		})
	}
}

func TestComputeCountsCappedAt99(t *testing.T) {
	h := chromeLikeHello()
	h.CipherSuites = make([]uint16, 0, 150)
	for i := range 150 {
		h.CipherSuites = append(h.CipherSuites, uint16(i+1))
	}
	a := strings.SplitN(Compute(h), "_", 2)[0]
	if a[4:6] != "99" {
		t.Errorf("cipher count = %q, want capped at 99 (section a = %q)", a[4:6], a)
	}
}

func TestComputeEmptySections(t *testing.T) {
	h := &tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS12}}
	got := Compute(h)
	want := "t12i000000_" + emptyHash + "_" + emptyHash
	if got != want {
		t.Fatalf("Compute(empty hello) = %q, want %q", got, want)
	}
}

func TestComputeNoSignatureAlgorithms(t *testing.T) {
	h := chromeLikeHello()
	h.SignatureSchemes = nil
	wantC := sha12("000d,0017,002b,0033") // no trailing "_" when sigalgs absent
	parts := strings.Split(Compute(h), "_")
	if parts[2] != wantC {
		t.Fatalf("section c without sigalgs = %q, want %q", parts[2], wantC)
	}
}

func TestStoreGetDelete(t *testing.T) {
	remoteAddr := "192.0.2.10:54321"
	fp := "t13d1516h2_8daaf6152771_02713d6af862"

	Delete(remoteAddr)
	Store(remoteAddr, fp)

	if got := Get(remoteAddr); got != fp {
		t.Fatalf("Get() = %q, want %q", got, fp)
	}

	Delete(remoteAddr)
	if got := Get(remoteAddr); got != "" {
		t.Fatalf("Get() after Delete() = %q, want empty string", got)
	}
}
