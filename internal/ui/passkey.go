package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"coraza-waf-mod/internal/security/passkey"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
)

// pkEnrollTTL bounds how long a passkey registration ceremony can take —
// same idea as twoFAPendingTTL, just for the settings-page enrollment flow
// instead of login.
const pkEnrollTTL = 5 * time.Minute

// pkEnrollStore holds the one in-flight passkey enrollment. Single-slot,
// like admin_totp_pending_secret: there's one admin account, so there's
// never more than one enrollment ceremony running at a time.
type pkEnrollStore struct {
	mu      sync.Mutex
	session *webauthn.SessionData
	name    string
	expires time.Time
}

func newPkEnrollStore() *pkEnrollStore { return &pkEnrollStore{} }

func (s *pkEnrollStore) begin(session *webauthn.SessionData, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session = session
	s.name = name
	s.expires = time.Now().Add(pkEnrollTTL)
}

// take returns and clears the pending ceremony, or ok=false if none is live.
func (s *pkEnrollStore) take() (session *webauthn.SessionData, name string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil || time.Now().After(s.expires) {
		s.session, s.name = nil, ""
		return nil, "", false
	}
	session, name = s.session, s.name
	s.session, s.name = nil, ""
	return session, name, true
}

// ── Settings: enrollment ─────────────────────────────────────────────────────

// passkeysCardData builds the settings card's rendering state: the list of
// registered passkeys plus whether this request is even in a context
// WebAuthn can work in (see passkey.IsSecureContext).
func (h *Handler) passkeysCardData(c echo.Context, extra map[string]any) map[string]any {
	rows, _ := h.db.ListWebAuthnCredentials()
	data := map[string]any{
		"AdminPath":     h.cfg.Admin.Path,
		"Passkeys":      rows,
		"SecureContext": passkey.IsSecureContext(c.Request()),
		"CSRF":          h.csrfFromContext(c),
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// BeginPasskeyEnrollment starts registering a new passkey for the admin
// account: builds the WebAuthn challenge, parks the session server-side,
// and returns the JSON options the browser's navigator.credentials.create()
// call needs.
func (h *Handler) BeginPasskeyEnrollment(c echo.Context) error {
	if !passkey.IsSecureContext(c.Request()) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Passkeys need HTTPS with a real hostname (or localhost). This admin panel isn't being reached that way right now.",
		})
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(c.Request().Body).Decode(&body)
	name := body.Name
	if name == "" {
		name = "Passkey"
	}

	creation, session, err := h.passkeys.BeginRegistration(c.Request())
	if err != nil {
		log.Printf("passkey enrollment: begin failed: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not start passkey registration."})
	}
	h.pkEnroll.begin(session, name)
	return c.JSON(http.StatusOK, creation)
}

// FinishPasskeyEnrollment validates the browser's attestation response and
// saves the new passkey.
func (h *Handler) FinishPasskeyEnrollment(c echo.Context) error {
	session, name, ok := h.pkEnroll.take()
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Enrollment expired. Start again."})
	}
	if err := h.passkeys.FinishRegistration(c.Request(), *session, name); err != nil {
		log.Printf("passkey enrollment: finish failed: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "That passkey couldn't be registered."})
	}
	log.Printf("admin passkey: registered %q", name)
	return h.renderPartial(c, "settings", "passkeys-card", h.passkeysCardData(c, nil))
}

// DeletePasskey removes one registered passkey. No re-auth challenge like
// DisableTOTP demands — a session already controls this account regardless,
// and removing one of possibly several passkeys is far less destructive
// than turning off the entire second factor.
func (h *Handler) DeletePasskey(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.db.DeleteWebAuthnCredential(id); err != nil {
		return err
	}
	log.Printf("admin passkey: removed credential id=%d", id)
	return h.renderPartial(c, "settings", "passkeys-card", h.passkeysCardData(c, nil))
}

// ── Login: passkey as the second factor ──────────────────────────────────────

// BeginPasskeyLogin starts a login ceremony for the pending (password
// already verified) login, mirroring LoginTOTPPost's cz_2fa-cookie gate.
func (h *Handler) BeginPasskeyLogin(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if _, locked := h.loginLimiter.blocked(ip); locked {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
	}
	_, entry := h.pendingEntry(c)
	if entry == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Sign-in expired. Enter your password again."})
	}
	assertion, session, err := h.passkeys.BeginLogin(c.Request())
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No passkeys are registered."})
	}
	entry.waSession = session
	return c.JSON(http.StatusOK, assertion)
}

// FinishPasskeyLogin validates the browser's assertion and, on success,
// completes the login exactly like a correct TOTP code would.
func (h *Handler) FinishPasskeyLogin(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if wait, locked := h.loginLimiter.blocked(ip); locked {
		log.Printf("admin login: rejected passkey attempt from %s (locked out for %s)", ip, wait.Round(time.Second))
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
	}
	token, entry := h.pendingEntry(c)
	if entry == nil || entry.waSession == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Sign-in expired. Enter your password again."})
	}

	if err := h.passkeys.FinishLogin(c.Request(), *entry.waSession); err != nil {
		entry.waSession = nil
		if h.loginLimiter.fail(ip) {
			log.Printf("admin login: %s locked out after %d failed attempts", ip, maxLoginFailures)
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
		}
		log.Printf("admin login: failed passkey attempt from %s", ip)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "That passkey didn't verify."})
	}

	h.twoFA.delete(token)
	c.SetCookie(&http.Cookie{
		Name: twoFACookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1,
		Secure: secureCookie(c),
	})
	h.loginLimiter.success(ip)
	log.Printf("admin login: successful login from %s (passkey)", ip)
	// JS-driven flow (fetch, not a form submit): tell the browser where to
	// go instead of issuing an HTTP redirect, which fetch would follow
	// internally without ever navigating the page.
	if err := h.startSession(c, ip); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal error. Please try again."})
	}
	return c.JSON(http.StatusOK, map[string]string{"redirect": h.cfg.Admin.Path})
}
