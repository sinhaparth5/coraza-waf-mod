package ja3

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

func TestStoreGetDelete(t *testing.T) {
	remoteAddr := "192.0.2.10:54321"
	hash := "0123456789abcdef0123456789abcdef"

	Delete(remoteAddr)
	Store(remoteAddr, hash)

	if got := Get(remoteAddr); got != hash {
		t.Fatalf("Get() = %q, want %q", got, hash)
	}

	Delete(remoteAddr)
	if got := Get(remoteAddr); got != "" {
		t.Fatalf("Get() after Delete() = %q, want empty string", got)
	}
}

func TestComputeFiltersGREASE(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:    []uint16{0x0a0a, 4865, 4866},
		Extensions:      []uint16{0x1a1a, 0, 10, 11},
		SupportedCurves: []tls.CurveID{0x2a2a, tls.X25519, tls.CurveP256},
		SupportedPoints: []uint8{0, 1},
	}
	want := md5.Sum([]byte("771,4865-4866,0-10-11,29-23,0-1"))
	if got := Compute(hello); got != hex.EncodeToString(want[:]) {
		t.Fatalf("Compute() = %s, want %x", got, want)
	}
}
