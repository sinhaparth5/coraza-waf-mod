package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/internal/security/totp"

	"github.com/labstack/echo/v4"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	// twoFACookie carries the opaque token proving the password step passed.
	// It is not a session: it only unlocks the code-entry form.
	twoFACookie = "cz_2fa"
	// twoFAPendingTTL is how long the admin has to enter a code after the
	// password step before having to sign in again.
	twoFAPendingTTL = 5 * time.Minute
	// emailCodeTTL / emailCodeResendWait bound the emailed recovery code:
	// valid for 10 minutes, re-sendable at most once a minute so the button
	// can't be used to flood the admin inbox.
	emailCodeTTL        = 10 * time.Minute
	emailCodeResendWait = time.Minute
	// backupCodeCount is how many one-time recovery codes enrollment hands out.
	backupCodeCount = 10
	// totpIssuer names this system in authenticator apps.
	totpIssuer = "Coraza WAF Mod"
)

// twoFAEntry is one password-verified login waiting for its second factor.
type twoFAEntry struct {
	expires          time.Time
	emailCode        string // emailed recovery code, "" until requested
	emailCodeExpires time.Time
	emailSentAt      time.Time
}

// twoFAStore holds pending two-factor logins in memory. In-process state is
// the same tradeoff loginLimiter already makes: one admin, one process, and
// losing entries on restart only means signing in again.
type twoFAStore struct {
	mu sync.Mutex
	m  map[string]*twoFAEntry
}

func newTwoFAStore() *twoFAStore { return &twoFAStore{m: make(map[string]*twoFAEntry)} }

// create registers a new pending login and returns its opaque token.
func (s *twoFAStore) create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Sweep expired entries while we're here — logins are rare enough that
	// this keeps the map bounded without a janitor goroutine.
	now := time.Now()
	for t, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, t)
		}
	}
	s.m[token] = &twoFAEntry{expires: now.Add(twoFAPendingTTL)}
	return token, nil
}

// get returns the live entry for token, or nil if unknown/expired.
func (s *twoFAStore) get(token string) *twoFAEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	if !ok {
		return nil
	}
	if time.Now().After(e.expires) {
		delete(s.m, token)
		return nil
	}
	return e
}

func (s *twoFAStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}

// ── Login: second step ───────────────────────────────────────────────────────

// pendingEntry resolves the cz_2fa cookie to a live pending login, returning
// the token alongside so handlers can delete it on success.
func (h *Handler) pendingEntry(c echo.Context) (string, *twoFAEntry) {
	ck, err := c.Cookie(twoFACookie)
	if err != nil || ck.Value == "" {
		return "", nil
	}
	return ck.Value, h.twoFA.get(ck.Value)
}

// beginTOTPStage is called by LoginPost after the password checks out but a
// second factor is required: it parks the login in twoFA and shows the code
// form. Deliberately does NOT reset loginLimiter — the password is already
// known-correct to whoever got here, so resetting on every password round
// would let an attacker launder TOTP guesses by re-posting the password.
func (h *Handler) beginTOTPStage(c echo.Context) error {
	token, err := h.twoFA.create()
	if err != nil {
		return h.renderLogin(c, "Internal error. Please try again.")
	}
	c.SetCookie(&http.Cookie{
		Name:     twoFACookie,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int(twoFAPendingTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie(c),
	})
	return h.renderLoginTOTP(c, http.StatusOK, "", "")
}

// LoginTOTPPost is the second authentication step: it accepts an
// authenticator code, a one-time backup code, or an emailed recovery code,
// in that order. Failures feed the same per-IP loginLimiter as password
// failures, so 2FA doesn't open a fresh brute-force surface.
func (h *Handler) LoginTOTPPost(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if wait, locked := h.loginLimiter.blocked(ip); locked {
		log.Printf("admin login: rejected 2FA attempt from %s (locked out for %s)", ip, wait.Round(time.Second))
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}

	token, entry := h.pendingEntry(c)
	if entry == nil {
		return h.renderLogin(c, "Sign-in expired. Enter your password again.")
	}

	code := strings.TrimSpace(c.FormValue("code"))
	if !h.verifySecondFactor(entry, code) {
		if h.loginLimiter.fail(ip) {
			log.Printf("admin login: %s locked out after %d failed attempts", ip, maxLoginFailures)
			return h.renderLoginStatus(c, http.StatusTooManyRequests,
				"Too many failed attempts. Try again later.")
		}
		log.Printf("admin login: failed 2FA attempt from %s", ip)
		return h.renderLoginTOTP(c, http.StatusOK, "Invalid code. Try again.", "")
	}

	h.twoFA.delete(token)
	c.SetCookie(&http.Cookie{
		Name: twoFACookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1,
		Secure: secureCookie(c),
	})
	h.loginLimiter.success(ip)
	log.Printf("admin login: successful login from %s (2FA)", ip)
	return h.issueSession(c)
}

// verifySecondFactor tries the three accepted proofs. TOTP replay is blocked
// by persisting the last accepted counter: a code is otherwise valid for its
// whole 30s window even after a successful login with it.
func (h *Handler) verifySecondFactor(entry *twoFAEntry, code string) bool {
	secret, err := h.db.GetTOTPSecret()
	if err != nil || secret == "" {
		// 2FA was disabled between the two steps; the password already passed.
		return err == nil
	}

	if ok, counter := totp.Validate(secret, code, time.Now()); ok {
		last, err := h.db.GetTOTPLastCounter()
		if err != nil || counter <= last {
			return false
		}
		if err := h.db.SetTOTPLastCounter(counter); err != nil {
			return false
		}
		return true
	}

	if used, _ := h.db.ConsumeTOTPBackupCode(hashBackupCode(code)); used {
		return true
	}

	if entry.emailCode != "" && time.Now().Before(entry.emailCodeExpires) &&
		subtle.ConstantTimeCompare([]byte(entry.emailCode), []byte(strings.TrimSpace(code))) == 1 {
		entry.emailCode = "" // single use
		return true
	}
	return false
}

// LoginTOTPEmail emails a one-time recovery code for the pending login via
// the existing Cloudflare Email Service mailer — the fallback for an admin
// whose authenticator (and backup codes) aren't at hand.
func (h *Handler) LoginTOTPEmail(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if _, locked := h.loginLimiter.blocked(ip); locked {
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}
	_, entry := h.pendingEntry(c)
	if entry == nil {
		return h.renderLogin(c, "Sign-in expired. Enter your password again.")
	}
	if h.sendLoginCode == nil || !h.emailRecoveryAvailable() {
		return h.renderLoginTOTP(c, http.StatusOK, "Email recovery is not configured.", "")
	}
	if since := time.Since(entry.emailSentAt); since < emailCodeResendWait {
		wait := (emailCodeResendWait - since).Round(time.Second)
		return h.renderLoginTOTP(c, http.StatusOK, "", fmt.Sprintf("A code was already sent. You can request another in %s.", wait))
	}

	code, err := randomDigits(6)
	if err != nil {
		return h.renderLoginTOTP(c, http.StatusOK, "Internal error. Please try again.", "")
	}
	entry.emailCode = code
	entry.emailCodeExpires = time.Now().Add(emailCodeTTL)
	entry.emailSentAt = time.Now()
	if err := h.sendLoginCode(code); err != nil {
		entry.emailCode = ""
		log.Printf("admin login: sending 2FA recovery code failed: %v", err)
		return h.renderLoginTOTP(c, http.StatusOK, "Sending the code failed. Check the email settings.", "")
	}
	log.Printf("admin login: 2FA recovery code emailed (requested from %s)", ip)
	return h.renderLoginTOTP(c, http.StatusOK, "", "Code sent to the configured admin email. It expires in 10 minutes.")
}

// emailRecoveryAvailable reports whether the mailer has enough config to
// deliver a recovery code; the login page only offers the option when true.
func (h *Handler) emailRecoveryAvailable() bool {
	if h.sendLoginCode == nil {
		return false
	}
	cfg, err := h.db.GetEmailConfig()
	return err == nil && cfg.Token != "" && cfg.To != ""
}

func (h *Handler) renderLoginTOTP(c echo.Context, status int, errMsg, notice string) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	return h.tmpls["login"].ExecuteTemplate(c.Response(), "login", map[string]any{
		"TOTPStage":      true,
		"Error":          errMsg,
		"Notice":         notice,
		"EmailAvailable": h.emailRecoveryAvailable(),
		"AdminPath":      h.cfg.Admin.Path,
	})
}

// ── Settings: enrollment ─────────────────────────────────────────────────────

// twoFACardData builds the settings card's default (no enrollment in
// progress) rendering state.
func (h *Handler) twoFACardData(extra map[string]any) map[string]any {
	enabled, _ := h.db.TOTPEnabled()
	data := map[string]any{
		"AdminPath":   h.cfg.Admin.Path,
		"TOTPEnabled": enabled,
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// StartTOTPEnrollment generates a fresh secret and shows the QR code +
// manual key with the confirm form. Nothing is enforced until the admin
// proves their authenticator works (ConfirmTOTPEnrollment).
func (h *Handler) StartTOTPEnrollment(c echo.Context) error {
	secret, err := totp.GenerateSecret()
	if err != nil {
		return err
	}
	if err := h.db.SetPendingTOTPSecret(secret); err != nil {
		return err
	}
	return h.renderTOTPEnrollment(c, secret, "")
}

func (h *Handler) renderTOTPEnrollment(c echo.Context, secret, errMsg string) error {
	email, _ := h.db.GetAdminEmail()
	uri := totp.ProvisioningURI(secret, email, totpIssuer)
	png, err := qrcode.Encode(uri, qrcode.Medium, 220)
	// template.URL: html/template's URL filter rejects data: URIs from plain
	// strings (rendered as ZgotmplZ); this one is built entirely server-side
	// from our own PNG bytes, never from user input.
	var qr template.URL
	if err == nil {
		qr = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	return h.renderPartial(c, "settings", "twofa-card", h.twoFACardData(map[string]any{
		"Enrolling": true,
		"QRDataURI": qr,
		"ManualKey": groupKey(secret),
		"EnrollErr": errMsg,
	}))
}

// ConfirmTOTPEnrollment checks a code against the pending secret and, on
// match, activates 2FA and hands out the one-time backup codes — shown once,
// stored only as SHA-256 hashes (they're high-entropy random, same reasoning
// as API keys).
func (h *Handler) ConfirmTOTPEnrollment(c echo.Context) error {
	pending, err := h.db.GetPendingTOTPSecret()
	if err != nil {
		return err
	}
	if pending == "" {
		return h.renderPartial(c, "settings", "twofa-card",
			h.twoFACardData(map[string]any{"CardErr": "No enrollment in progress. Start again."}))
	}
	code := c.FormValue("code")
	if ok, _ := totp.Validate(pending, code, time.Now()); !ok {
		return h.renderTOTPEnrollment(c, pending,
			"That code didn't match. Check the app and try again.")
	}

	codes, hashes, err := newBackupCodes(backupCodeCount)
	if err != nil {
		return err
	}
	if err := h.db.EnableTOTP(hashes); err != nil {
		return err
	}
	log.Printf("admin 2FA: enabled")
	return h.renderPartial(c, "settings", "twofa-card", h.twoFACardData(map[string]any{
		"BackupCodes": codes,
	}))
}

// DisableTOTP turns 2FA off. It demands a current authenticator or backup
// code, not just the session cookie: a hijacked session shouldn't be able to
// quietly remove the second factor.
func (h *Handler) DisableTOTP(c echo.Context) error {
	secret, err := h.db.GetTOTPSecret()
	if err != nil {
		return err
	}
	code := c.FormValue("code")
	ok, _ := totp.Validate(secret, code, time.Now())
	if !ok {
		if used, _ := h.db.ConsumeTOTPBackupCode(hashBackupCode(code)); used {
			ok = true
		}
	}
	if !ok {
		return h.renderPartial(c, "settings", "twofa-card",
			h.twoFACardData(map[string]any{"CardErr": "Enter a valid authenticator or backup code to disable 2FA."}))
	}
	if err := h.db.DisableTOTP(); err != nil {
		return err
	}
	log.Printf("admin 2FA: disabled")
	return h.renderPartial(c, "settings", "twofa-card", h.twoFACardData(nil))
}

// ── Code helpers ─────────────────────────────────────────────────────────────

// newBackupCodes returns n one-time codes in display form ("XXXX-XXXX",
// base32 alphabet) plus their storage hashes.
func newBackupCodes(n int) (codes, hashes []string, err error) {
	for i := 0; i < n; i++ {
		b := make([]byte, 5) // 40 bits → 8 base32 chars
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		code := raw[:4] + "-" + raw[4:]
		codes = append(codes, code)
		hashes = append(hashes, hashBackupCode(code))
	}
	return codes, hashes, nil
}

// hashBackupCode normalizes (case, separators) and hashes a backup code the
// same way at generation and login, so re-typing variants still match.
func hashBackupCode(code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("cz-backup:" + norm))
	return hex.EncodeToString(sum[:])
}

// randomDigits returns n crypto-random decimal digits (the emailed code).
// Bytes ≥ 250 are rejected rather than folded so every digit is equally
// likely (256 % 10 != 0).
func randomDigits(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, 16)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= 250 || len(out) == n {
				continue
			}
			out = append(out, '0'+b%10)
		}
	}
	return string(out), nil
}

// groupKey chunks a base32 secret into 4-char groups for manual entry.
func groupKey(secret string) string {
	var sb strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
