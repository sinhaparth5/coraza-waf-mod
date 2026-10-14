package passkey

import (
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"palisade/internal/storage"
)

func newManager(t *testing.T) (*Manager, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), db
}

func TestIsSecureContext(t *testing.T) {
	tests := []struct {
		host, proto string
		tls         bool
		want        bool
	}{
		{"example.com", "", true, true},
		{"example.com", "HTTPS", false, true},
		{"localhost:8080", "", false, true},
		{"127.0.0.1", "", false, true},
		{"[::1]:8080", "", false, true},
		{"example.com", "", false, false},
		{"203.0.113.5:8080", "http", false, false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = tt.host
		if tt.proto != "" {
			r.Header.Set("X-Forwarded-Proto", tt.proto)
		}
		if tt.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := IsSecureContext(r); got != tt.want {
			t.Errorf("IsSecureContext(host=%q proto=%q tls=%v) = %v", tt.host, tt.proto, tt.tls, got)
		}
	}
}

func TestNilManager(t *testing.T) {
	var m *Manager
	r := httptest.NewRequest("GET", "/", nil)
	if ok, err := m.Enabled(); ok || err != nil {
		t.Errorf("Enabled() = %v, %v", ok, err)
	}
	if _, _, err := m.BeginRegistration(r); err == nil {
		t.Error("BeginRegistration on nil manager should error")
	}
	if err := m.FinishRegistration(r, webauthn.SessionData{}, ""); err == nil {
		t.Error("FinishRegistration on nil manager should error")
	}
	if _, _, err := m.BeginLogin(r); err == nil {
		t.Error("BeginLogin on nil manager should error")
	}
	if err := m.FinishLogin(r, webauthn.SessionData{}); err == nil {
		t.Error("FinishLogin on nil manager should error")
	}
}

func TestCeremonies(t *testing.T) {
	m, db := newManager(t)
	r := httptest.NewRequest("POST", "/", strings.NewReader("{}"))
	r.Host = "localhost:8080"

	if ok, err := m.Enabled(); ok || err != nil {
		t.Fatalf("Enabled() = %v, %v before any passkey", ok, err)
	}

	creation, session, err := m.BeginRegistration(r)
	if err != nil {
		t.Fatal(err)
	}
	if creation.Response.RelyingParty.ID != "localhost" || len(session.Challenge) == 0 {
		t.Fatalf("unexpected creation options: %+v", creation.Response.RelyingParty)
	}
	// A bogus browser response must be rejected, never stored.
	if err := m.FinishRegistration(r, *session, ""); err == nil {
		t.Fatal("FinishRegistration accepted an invalid response")
	}

	if _, _, err := m.BeginLogin(r); err == nil || !strings.Contains(err.Error(), "no passkeys") {
		t.Fatalf("BeginLogin with no creds: %v", err)
	}

	// A corrupt stored row is skipped, so login still reports no usable passkeys.
	if err := db.AddWebAuthnCredential("corrupt", "Broken", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.BeginLogin(r); err == nil {
		t.Fatal("BeginLogin should ignore unreadable credentials")
	}

	// A well-formed credential makes login startable.
	if err := db.AddWebAuthnCredential(credentialID([]byte{1, 2, 3}), "Key", []byte(`{"id":"AQID"}`)); err != nil {
		t.Fatal(err)
	}
	assertion, session, err := m.BeginLogin(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(assertion.Response.AllowedCredentials) != 1 {
		t.Fatalf("allowed credentials = %d", len(assertion.Response.AllowedCredentials))
	}
	if err := m.FinishLogin(r, *session); err == nil {
		t.Fatal("FinishLogin accepted an invalid assertion")
	}
}

func TestBadRPID(t *testing.T) {
	m, _ := newManager(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = ""
	if _, _, err := m.BeginRegistration(r); err == nil {
		t.Error("empty host should fail config")
	}
	if err := m.FinishRegistration(r, webauthn.SessionData{}, ""); err == nil {
		t.Error("empty host should fail config")
	}
	if _, _, err := m.BeginLogin(r); err == nil {
		t.Error("empty host should fail config")
	}
	if err := m.FinishLogin(r, webauthn.SessionData{}); err == nil {
		t.Error("empty host should fail config")
	}
}
