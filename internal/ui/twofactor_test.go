package ui

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/security/totp"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

const (
	twoFATestEmail    = "admin@example.com"
	twoFATestPassword = "hunter22hunter22"
)

// newTestLoginHandler builds a Handler with real templates and a seeded
// admin, registered on a real Echo instance, so the two-step login flow is
// exercised end to end via httptest.
func newTestLoginHandler(t *testing.T) (*Handler, *echo.Echo, *storage.DB) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.SeedAdmin(twoFATestEmail, twoFATestPassword); err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		cfg:          &config.Config{Admin: config.AdminConfig{Path: "/admin"}},
		db:           db,
		staticJS:     fstest.MapFS{},
		staticImgs:   fstest.MapFS{},
		loginLimiter: newLoginLimiter(),
		twoFA:        newTwoFAStore(),
	}
	if err := h.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	h.Register(e)
	return h, e, db
}

// enableTOTP turns 2FA on directly through storage and returns the secret.
func enableTOTP(t *testing.T, db *storage.DB, backupHashes ...string) string {
	t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPendingTOTPSecret(secret); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableTOTP(backupHashes); err != nil {
		t.Fatal(err)
	}
	return secret
}

func postForm(e *echo.Echo, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func cookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name && ck.Value != "" {
			return ck
		}
	}
	return nil
}

func passwordStep(t *testing.T, e *echo.Echo) *http.Cookie {
	t.Helper()
	rec := postForm(e, "/admin/login", url.Values{
		"email": {twoFATestEmail}, "password": {twoFATestPassword},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("password step = %d, want 200 (TOTP stage)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Two-factor authentication") {
		t.Fatal("password step did not render the TOTP stage")
	}
	if cookieByName(rec, sessionCookie) != nil {
		t.Fatal("password step alone must not issue a session cookie")
	}
	ck := cookieByName(rec, twoFACookie)
	if ck == nil {
		t.Fatal("password step did not set the cz_2fa cookie")
	}
	return ck
}

// TestLoginTOTPFlow walks the full two-step login: password → TOTP stage →
// code → session, and checks the same code can't be replayed afterwards.
func TestLoginTOTPFlow(t *testing.T) {
	_, e, db := newTestLoginHandler(t)
	secret := enableTOTP(t, db)

	pending := passwordStep(t, e)
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := postForm(e, "/admin/login/totp", url.Values{"code": {code}}, pending)
	if rec.Code != http.StatusFound {
		t.Fatalf("TOTP step with valid code = %d, want 302", rec.Code)
	}
	if cookieByName(rec, sessionCookie) == nil {
		t.Fatal("valid TOTP code did not issue a session cookie")
	}

	// Replay: the exact code that just logged in must be rejected for a new
	// pending login within the same time window.
	pending = passwordStep(t, e)
	rec = postForm(e, "/admin/login/totp", url.Values{"code": {code}}, pending)
	if rec.Code != http.StatusOK || cookieByName(rec, sessionCookie) != nil {
		t.Fatalf("replayed TOTP code: status %d, want 200 re-prompt with no session", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid code") {
		t.Error("replayed code did not render the invalid-code error")
	}
}

// TestLoginTOTPRequiresPendingToken checks the code endpoint is useless
// without having passed the password step (no cz_2fa cookie).
func TestLoginTOTPRequiresPendingToken(t *testing.T) {
	_, e, db := newTestLoginHandler(t)
	secret := enableTOTP(t, db)
	code, _ := totp.Code(secret, time.Now())

	rec := postForm(e, "/admin/login/totp", url.Values{"code": {code}})
	if rec.Code != http.StatusOK || cookieByName(rec, sessionCookie) != nil {
		t.Fatalf("TOTP step without pending cookie: status %d, session issued: %v",
			rec.Code, cookieByName(rec, sessionCookie) != nil)
	}
	if !strings.Contains(rec.Body.String(), "Sign-in expired") {
		t.Error("missing pending token did not fall back to the password page")
	}
}

// TestLoginTOTPWrongCodesHitLimiter checks failed codes feed the same per-IP
// lockout as failed passwords, so 2FA isn't a fresh brute-force surface.
func TestLoginTOTPWrongCodesHitLimiter(t *testing.T) {
	_, e, db := newTestLoginHandler(t)
	enableTOTP(t, db)

	pending := passwordStep(t, e)
	var last *httptest.ResponseRecorder
	for i := 0; i < maxLoginFailures; i++ {
		last = postForm(e, "/admin/login/totp", url.Values{"code": {"000000"}}, pending)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong codes: status %d, want 429 lockout", maxLoginFailures, last.Code)
	}
	// And the lockout also blocks the password step, like any other failure.
	rec := postForm(e, "/admin/login", url.Values{
		"email": {twoFATestEmail}, "password": {twoFATestPassword},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("password step during lockout = %d, want 429", rec.Code)
	}
}

// TestLoginTOTPBackupCodeSingleUse checks a backup code signs in exactly once.
func TestLoginTOTPBackupCodeSingleUse(t *testing.T) {
	_, e, db := newTestLoginHandler(t)
	const backup = "ABCD-EFGH"
	enableTOTP(t, db, hashBackupCode(backup))

	pending := passwordStep(t, e)
	// Lowercase with spaces: normalization must still match.
	rec := postForm(e, "/admin/login/totp", url.Values{"code": {"abcd efgh"}}, pending)
	if rec.Code != http.StatusFound || cookieByName(rec, sessionCookie) == nil {
		t.Fatalf("backup code login: status %d, want 302 with session", rec.Code)
	}

	pending = passwordStep(t, e)
	rec = postForm(e, "/admin/login/totp", url.Values{"code": {backup}}, pending)
	if rec.Code != http.StatusOK || cookieByName(rec, sessionCookie) != nil {
		t.Fatalf("reused backup code: status %d, want rejection", rec.Code)
	}
}

// TestLoginTOTPEmailRecovery checks the emailed recovery code path: send,
// resend throttle, and signing in with the mailed code.
func TestLoginTOTPEmailRecovery(t *testing.T) {
	h, e, db := newTestLoginHandler(t)
	enableTOTP(t, db)
	if err := db.SetEmailConfig(storage.EmailConfig{To: "ops@example.com", Token: "cf-token"}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	h.sendLoginCode = func(code string) error { sent = append(sent, code); return nil }

	pending := passwordStep(t, e)
	rec := postForm(e, "/admin/login/totp/email", url.Values{}, pending)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Code sent") {
		t.Fatalf("email request: status %d, body missing confirmation", rec.Code)
	}
	if len(sent) != 1 || len(sent[0]) != 6 {
		t.Fatalf("sent codes = %v, want one 6-digit code", sent)
	}

	// Immediate resend is throttled and must not send a second mail.
	rec = postForm(e, "/admin/login/totp/email", url.Values{}, pending)
	if len(sent) != 1 || !strings.Contains(rec.Body.String(), "already sent") {
		t.Fatalf("resend not throttled (sent=%d)", len(sent))
	}

	rec = postForm(e, "/admin/login/totp", url.Values{"code": {sent[0]}}, pending)
	if rec.Code != http.StatusFound || cookieByName(rec, sessionCookie) == nil {
		t.Fatalf("emailed code login: status %d, want 302 with session", rec.Code)
	}

	// The mailed code is single-use: it must not work for a second login.
	pending = passwordStep(t, e)
	rec = postForm(e, "/admin/login/totp", url.Values{"code": {sent[0]}}, pending)
	if rec.Code != http.StatusOK || cookieByName(rec, sessionCookie) != nil {
		t.Fatalf("reused emailed code: status %d, want rejection", rec.Code)
	}
}

// TestLoginWithoutTOTPSkipsSecondStep checks the password-only flow is
// unchanged while 2FA is off.
func TestLoginWithoutTOTPSkipsSecondStep(t *testing.T) {
	_, e, _ := newTestLoginHandler(t)
	rec := postForm(e, "/admin/login", url.Values{
		"email": {twoFATestEmail}, "password": {twoFATestPassword},
	})
	if rec.Code != http.StatusFound || cookieByName(rec, sessionCookie) == nil {
		t.Fatalf("password-only login: status %d, want direct 302 with session", rec.Code)
	}
}

// TestTwoFACardStates renders the settings card in its four states.
func TestTwoFACardStates(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	render := func(data map[string]any) string {
		data["AdminPath"] = "/admin"
		var buf bytes.Buffer
		if err := h.tmpls["settings"].ExecuteTemplate(&buf, "twofa-card", data); err != nil {
			t.Fatalf("execute twofa-card: %v", err)
		}
		return buf.String()
	}

	off := render(map[string]any{"TOTPEnabled": false})
	if !strings.Contains(off, "/admin/settings/2fa/start") {
		t.Error("disabled state missing the Enable 2FA form")
	}
	on := render(map[string]any{"TOTPEnabled": true})
	if !strings.Contains(on, "/admin/settings/2fa/disable") {
		t.Error("enabled state missing the disable form")
	}
	enrolling := render(map[string]any{"Enrolling": true, "QRDataURI": template.URL("data:image/png;base64,AAAA"), "ManualKey": "ABCD EFGH"})
	for _, want := range []string{"data:image/png;base64,AAAA", "ABCD EFGH", "/admin/settings/2fa/confirm"} {
		if !strings.Contains(enrolling, want) {
			t.Errorf("enrolling state missing %q", want)
		}
	}
	done := render(map[string]any{"TOTPEnabled": true, "BackupCodes": []string{"AAAA-BBBB", "CCCC-DDDD"}})
	for _, want := range []string{"AAAA-BBBB", "CCCC-DDDD", "won't be shown again"} {
		if !strings.Contains(done, want) {
			t.Errorf("backup-codes state missing %q", want)
		}
	}
}

// TestTOTPEnrollmentHandlers drives the settings card's handler flow
// directly: start shows a QR + manual key, a wrong code re-prompts without
// enabling, the right code enables and prints backup codes, and disabling
// demands a current code.
func TestTOTPEnrollmentHandlers(t *testing.T) {
	h, _, db := newTestLoginHandler(t)
	e := echo.New()

	invoke := func(handler echo.HandlerFunc, form url.Values) (*httptest.ResponseRecorder, error) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		return rec, handler(e.NewContext(req, rec))
	}

	rec, err := invoke(h.StartTOTPEnrollment, url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), "data:image/png;base64,") {
		t.Fatal("enrollment start did not render a QR code")
	}
	secret, _ := db.GetPendingTOTPSecret()
	if secret == "" {
		t.Fatal("enrollment start did not store a pending secret")
	}

	rec, err = invoke(h.ConfirmTOTPEnrollment, url.Values{"code": {"000000"}})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, _ := db.TOTPEnabled(); enabled {
		t.Fatal("wrong confirm code enabled 2FA")
	}
	if !strings.Contains(rec.Body.String(), "didn") {
		t.Error("wrong confirm code did not re-prompt with an error")
	}

	code, _ := totp.Code(secret, time.Now())
	rec, err = invoke(h.ConfirmTOTPEnrollment, url.Values{"code": {code}})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, _ := db.TOTPEnabled(); !enabled {
		t.Fatal("valid confirm code did not enable 2FA")
	}
	if got := strings.Count(rec.Body.String(), "select-all"); got < backupCodeCount {
		t.Errorf("confirm rendered %d backup-code cells, want %d", got, backupCodeCount)
	}

	// Disable requires a real code — the session alone isn't enough.
	if _, err = invoke(h.DisableTOTP, url.Values{"code": {"000000"}}); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := db.TOTPEnabled(); !enabled {
		t.Fatal("2FA disabled without a valid code")
	}
	code, _ = totp.Code(secret, time.Now())
	if _, err = invoke(h.DisableTOTP, url.Values{"code": {code}}); err != nil {
		t.Fatal(err)
	}
	if enabled, _ := db.TOTPEnabled(); enabled {
		t.Fatal("valid code did not disable 2FA")
	}
}
