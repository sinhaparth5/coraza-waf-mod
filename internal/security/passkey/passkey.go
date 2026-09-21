// Package passkey wraps github.com/go-webauthn/webauthn for the admin
// login's optional WebAuthn/passkey second factor (issue #78). There is
// exactly one admin account (see storage's meta-table auth), so this
// package deliberately has no concept of multiple users — just one
// account that may hold zero or more registered passkeys.
package passkey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"coraza-waf-mod/internal/storage"
)

// Manager builds a per-request *webauthn.WebAuthn and adapts storage rows
// to the library's User/Credential shapes.
type Manager struct {
	db *storage.DB
}

func New(db *storage.DB) *Manager {
	return &Manager{db: db}
}

// adminUser adapts the single admin account to webauthn.User.
type adminUser struct {
	handle []byte
	email  string
	creds  []webauthn.Credential
}

func (u *adminUser) WebAuthnID() []byte                         { return u.handle }
func (u *adminUser) WebAuthnName() string                       { return u.email }
func (u *adminUser) WebAuthnDisplayName() string                { return u.email }
func (u *adminUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// user loads the admin account plus its currently-registered credentials.
func (m *Manager) user() (*adminUser, []storage.WebAuthnCredential, error) {
	handle, err := m.db.GetOrCreateWebAuthnHandle()
	if err != nil {
		return nil, nil, err
	}
	email, err := m.db.GetAdminEmail()
	if err != nil {
		return nil, nil, err
	}
	rows, err := m.db.ListWebAuthnCredentials()
	if err != nil {
		return nil, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(r.Data, &c); err != nil {
			continue // corrupt/unreadable row — skip rather than fail the whole login
		}
		creds = append(creds, c)
	}
	return &adminUser{handle: handle, email: email, creds: creds}, rows, nil
}

// Enabled reports whether the admin has at least one registered passkey. A
// nil Manager (e.g. a Handler built without going through NewHandler, as
// some tests do) behaves as "not available" rather than panicking — same
// nil-receiver-guard pattern as asn.Lookup.Lookup.
func (m *Manager) Enabled() (bool, error) {
	if m == nil {
		return false, nil
	}
	return m.db.WebAuthnEnabled()
}

// IsSecureContext reports whether the request was served in a context
// WebAuthn can actually work in: real TLS, or localhost (the one exception
// the spec itself carves out for plain HTTP). This project also supports
// plain-HTTP and bare-IP deployments, where a passkey ceremony would just
// fail in the browser with a confusing error — callers use this to hide
// the passkey option entirely rather than offer something broken.
func IsSecureContext(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(fwd, "https") {
		return true
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// config builds the RPID/RPOrigins for the domain this request actually
// arrived on. Self-hosted deployments have no single fixed domain the way
// most WebAuthn relying parties do, so this is derived per request rather
// than configured once at startup — a passkey registered while reaching
// the admin panel at one hostname simply won't validate from another,
// which is the correct, spec-intended behavior (it's what makes passkeys
// phishing-resistant in the first place).
func (m *Manager) config(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	scheme := "https"
	if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "http"
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "Coraza WAF Mod",
		RPID:          host,
		RPOrigins:     []string{scheme + "://" + r.Host},
	})
}

// BeginRegistration starts enrolling a new passkey for the admin account.
// The returned SessionData must be held (server-side only — never handed
// to the browser) until FinishRegistration.
func (m *Manager) BeginRegistration(r *http.Request) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if m == nil {
		return nil, nil, fmt.Errorf("passkeys unavailable")
	}
	w, err := m.config(r)
	if err != nil {
		return nil, nil, err
	}
	user, _, err := m.user()
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := w.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	return creation, session, nil
}

// FinishRegistration validates the browser's response and stores the new
// credential under name.
func (m *Manager) FinishRegistration(r *http.Request, session webauthn.SessionData, name string) error {
	if m == nil {
		return fmt.Errorf("passkeys unavailable")
	}
	w, err := m.config(r)
	if err != nil {
		return err
	}
	user, _, err := m.user()
	if err != nil {
		return err
	}
	cred, err := w.FinishRegistration(user, session, r)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if name == "" {
		name = "Passkey"
	}
	return m.db.AddWebAuthnCredential(credentialID(cred.ID), name, data)
}

// BeginLogin starts a login ceremony scoped to the admin's own registered
// credentials. Returns an error if none are registered.
func (m *Manager) BeginLogin(r *http.Request) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if m == nil {
		return nil, nil, fmt.Errorf("passkeys unavailable")
	}
	w, err := m.config(r)
	if err != nil {
		return nil, nil, err
	}
	user, _, err := m.user()
	if err != nil {
		return nil, nil, err
	}
	// Check the successfully-parsed credentials, not the raw row count —
	// a row that failed to unmarshal in m.user() is already excluded from
	// user.creds, and BeginLogin against zero real credentials would
	// otherwise surface as a confusing library-internal error instead of
	// this clear one.
	if len(user.creds) == 0 {
		return nil, nil, fmt.Errorf("no passkeys registered")
	}
	assertion, session, err := w.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}
	return assertion, session, nil
}

// FinishLogin validates the browser's assertion and bumps the matched
// credential's stored sign counter (cloned-authenticator detection).
func (m *Manager) FinishLogin(r *http.Request, session webauthn.SessionData) error {
	if m == nil {
		return fmt.Errorf("passkeys unavailable")
	}
	w, err := m.config(r)
	if err != nil {
		return err
	}
	user, _, err := m.user()
	if err != nil {
		return err
	}
	cred, err := w.FinishLogin(user, session, r)
	if err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return m.db.TouchWebAuthnCredential(credentialID(cred.ID), data)
}

// credentialID returns the storage lookup key for a raw credential ID —
// base64url without padding, matching what the browser/library use
// elsewhere in the wire protocol.
func credentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}
