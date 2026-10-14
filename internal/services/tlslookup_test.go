package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"palisade/internal/storage"
)

// TestRegistryTLSLookups drives SNI cert selection and the autocert host
// policy through a real Reload, so the custom/auto/none branches are wired
// exactly as the TLS listener sees them.
func TestRegistryTLSLookups(t *testing.T) {
	t.Chdir(t.TempDir())
	db, err := storage.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, s := range [][2]string{{"custom", "custom.test"}, {"auto", "Auto.test"}, {"plain", "plain.test"}} {
		if err := db.AddService(s[0], s[1], "", "http://10.0.0.1", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	svcs, _ := db.ListServices()
	certPEM, keyPEM := selfSignedPair(t, "custom.test")
	certPath, keyPath, exp, err := SaveCustomCert("custom", certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.SetServiceTLS(svcs[0].ID, "custom", certPath, keyPath, exp.String())
	_ = db.SetServiceTLS(svcs[1].ID, "auto", "", "", "")

	r, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	get := r.GetCertificateFunc(nil)
	if c, err := get(&tls.ClientHelloInfo{ServerName: "CUSTOM.test"}); err != nil || c == nil {
		t.Errorf("custom cert by SNI: %v", err)
	}
	if _, err := get(&tls.ClientHelloInfo{ServerName: "auto.test"}); err == nil {
		t.Error("auto host with no autocert manager should fail the handshake")
	}
	if _, err := get(&tls.ClientHelloInfo{ServerName: "plain.test"}); err == nil {
		t.Error("host with no TLS config should fail the handshake")
	}

	policy := r.HostPolicy()
	if err := policy(context.Background(), "AUTO.test"); err != nil {
		t.Errorf("auto host rejected: %v", err)
	}
	if err := policy(context.Background(), "custom.test"); err == nil {
		t.Error("non-auto host allowed by autocert policy")
	}
}

func TestSaveCustomCertRejectsMismatchedKey(t *testing.T) {
	t.Chdir(t.TempDir())
	certPEM, _ := selfSignedPair(t, "a.test")
	_, otherKey := selfSignedPair(t, "b.test")
	if _, _, _, err := SaveCustomCert("a", certPEM, otherKey); err == nil {
		t.Error("mismatched key accepted")
	}
	if _, _, err := SavePoolCert(1, certPEM, otherKey); err == nil {
		t.Error("mismatched pool key accepted")
	}
	if _, err := LoadCertificate("missing.pem", "missing.key"); err == nil {
		t.Error("missing files loaded")
	}
}

// selfSignedPair is selfSignedPEM plus the matching private key.
func selfSignedPair(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}
