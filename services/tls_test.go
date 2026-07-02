package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedPEM generates a throwaway cert covering the given SANs (and CN if
// sans is empty), returning the PEM-encoded certificate.
func selfSignedPEM(t *testing.T, cn string, sans []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertCoversHost(t *testing.T) {
	cases := []struct {
		name string
		cn   string
		sans []string
		host string
		ok   bool
	}{
		{"exact SAN", "example.com", []string{"example.com"}, "example.com", true},
		{"other domain rejected", "example.com", []string{"example.com"}, "example2.com", false},
		{"wildcard covers subdomain", "example.com", []string{"example.com", "*.example.com"}, "app.example.com", true},
		{"wildcard does not cover apex of other domain", "example.com", []string{"*.example.com"}, "example2.com", false},
		{"host with port", "example.com", []string{"example.com"}, "example.com:8443", true},
		{"case-insensitive", "example.com", []string{"example.com"}, "EXAMPLE.com", true},
		{"CN-only legacy cert", "legacy.example.com", nil, "legacy.example.com", true},
		{"CN-only mismatch rejected", "legacy.example.com", nil, "other.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CertCoversHost(selfSignedPEM(t, tc.cn, tc.sans), tc.host)
			if tc.ok && err != nil {
				t.Errorf("expected cert (CN=%s SANs=%v) to cover %q, got: %v", tc.cn, tc.sans, tc.host, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("expected cert (CN=%s SANs=%v) to NOT cover %q", tc.cn, tc.sans, tc.host)
			}
		})
	}
}

func TestCertCoversHostBadPEM(t *testing.T) {
	if err := CertCoversHost([]byte("not a pem"), "example.com"); err == nil {
		t.Error("expected error for invalid PEM input")
	}
}
