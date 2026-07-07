package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testVisitorID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

// solvePoW brute-forces the challenge like the browser does (~256 tries).
func solvePoW(nonce string) uint64 {
	for sol := uint64(0); ; sol++ {
		h := sha256.Sum256([]byte(nonce + strconv.FormatUint(sol, 10)))
		if h[0] == 0x00 {
			return sol
		}
	}
}

func TestCookieCarriesVisitorID(t *testing.T) {
	c := New("secret", 3600, 5)
	expiry := time.Now().Unix() + 3600

	value := c.buildCookieValue(expiry, testVisitorID)
	vid, ok := c.parseCookie(value)
	if !ok {
		t.Fatal("freshly built cookie did not verify")
	}
	if vid != testVisitorID {
		t.Fatalf("parseCookie visitor ID = %q, want %q", vid, testVisitorID)
	}

	// Empty visitor ID (fingerprint blocked/failed) still verifies.
	vid, ok = c.parseCookie(c.buildCookieValue(expiry, ""))
	if !ok || vid != "" {
		t.Fatalf("empty-vid cookie: vid=%q ok=%v, want \"\" true", vid, ok)
	}
}

func TestCookieVisitorIDTamperRejected(t *testing.T) {
	c := New("secret", 3600, 5)
	expiry := time.Now().Unix() + 3600
	value := c.buildCookieValue(expiry, testVisitorID)

	// Swap in a different visitor ID without re-signing.
	forged := fmt.Sprintf("%d.%s.%s", expiry, "ffffffffffffffffffffffffffffffff",
		value[len(value)-32:])
	if _, ok := c.parseCookie(forged); ok {
		t.Fatal("cookie with swapped visitor ID must not verify")
	}
}

func TestLegacyCookieStillValid(t *testing.T) {
	c := New("secret", 3600, 5)
	expiry := time.Now().Unix() + 3600

	// Pre-fingerprint format: "expiry.sig" with HMAC("cz-pass:expiry").
	legacy := func() string {
		mac := newTestMAC(c.secret, fmt.Sprintf("cz-pass:%d", expiry))
		return fmt.Sprintf("%d.%s", expiry, mac)
	}()

	vid, ok := c.parseCookie(legacy)
	if !ok {
		t.Fatal("legacy two-part cookie must stay valid after upgrade")
	}
	if vid != "" {
		t.Fatalf("legacy cookie visitor ID = %q, want empty", vid)
	}
}

func TestSanitizeVisitorID(t *testing.T) {
	cases := map[string]string{
		testVisitorID:                 testVisitorID, // normal FingerprintJS hash
		"":                            "",
		"short":                       "", // below minimum length
		"has.dot.inside01":            "", // would break the cookie format
		"<script>xx</script>abcdefgh": "", // junk
	}
	for in, want := range cases {
		if got := sanitizeVisitorID(in); got != want {
			t.Errorf("sanitizeVisitorID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVerifyFlowEndToEnd solves a real challenge, posts it with a visitor ID,
// and checks the issued cookie authenticates and yields that ID.
func TestVerifyFlowEndToEnd(t *testing.T) {
	c := New("secret", 3600, 5)

	nonce := "74657374"
	exp := time.Now().Unix() + 120
	body, _ := json.Marshal(map[string]any{
		"nonce":      nonce,
		"exp":        exp,
		"sig":        c.signNonce(nonce, exp),
		"solution":   solvePoW(nonce),
		"visitor_id": testVisitorID,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_cz/verify", bytes.NewReader(body))
	c.ServeVerify(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify returned %d: %s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	follow := httptest.NewRequest(http.MethodGet, "/", nil)
	follow.AddCookie(cookies[0])
	if !c.PassedChallenge(follow) {
		t.Fatal("request with issued cookie did not pass the challenge gate")
	}
	if got := c.VisitorID(follow); got != testVisitorID {
		t.Fatalf("VisitorID() = %q, want %q", got, testVisitorID)
	}
}

func TestFirstAutomationSignal(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"none", nil, ""},
		{"empty slice", []string{}, ""},
		{"single known", []string{"webdriver"}, "webdriver"},
		{"unknown ignored", []string{"totally-legit", "chrome"}, ""},
		{"known after unknown", []string{"junk", "cdc"}, "cdc"},
		{"first known wins", []string{"selenium", "phantom"}, "selenium"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstAutomationSignal(tc.in); got != tc.want {
				t.Errorf("firstAutomationSignal(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestVerifyRefusesAutomation posts a fully valid, solved challenge that also
// reports an automation-leakage signal, and checks the server refuses the
// bypass cookie (so the client stays challenged and can't scrape).
func TestVerifyRefusesAutomation(t *testing.T) {
	c := New("secret", 3600, 5)
	nonce := "6175746f6d6174"
	exp := time.Now().Unix() + 120

	post := func(automation []string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"nonce":      nonce,
			"exp":        exp,
			"sig":        c.signNonce(nonce, exp),
			"solution":   solvePoW(nonce),
			"visitor_id": testVisitorID,
			"automation": automation,
		})
		rec := httptest.NewRecorder()
		c.ServeVerify(rec, httptest.NewRequest(http.MethodPost, "/_cz/verify", bytes.NewReader(body)))
		return rec
	}

	// A leaked automation signal must be refused with no cookie issued.
	rec := post([]string{"webdriver"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("verify with webdriver signal returned %d, want 403", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no bypass cookie must be issued to an automated browser")
	}

	// An unrecognized token is ignored — a genuine solve still passes.
	rec = post([]string{"just-a-normal-string"})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify with unknown token returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 1 {
		t.Fatal("valid solve with no real automation signal must issue a cookie")
	}
}

// TestServePageRenders requests a real signed challenge URL and checks the
// page renders with the visitor's host, the reference ID, and the logo.
func TestServePageRenders(t *testing.T) {
	c := New("secret", 3600, 5)

	req := httptest.NewRequest(http.MethodGet, c.ChallengeURL("/account"), nil)
	req.Host = "app.example.com"
	rec := httptest.NewRecorder()
	c.ServePage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ServePage returned %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"app.example.com",       // visitor's domain is the headline
		"Reference ID:",         // nonce-derived support reference
		"/_cz/logo.svg",         // favicon + wordmark + footer logo
		"/_cz/fp.js",            // fingerprint bundle still loaded
		"detectAutomation",      // automated-browser leakage probe ships in the page
		"Checking your browser", // headline copy
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %q", want)
		}
	}
}

func TestServeFingerprintJS(t *testing.T) {
	c := New("secret", 3600, 5)
	rec := httptest.NewRecorder()
	c.ServeFingerprintJS(rec, httptest.NewRequest(http.MethodGet, "/_cz/fp.js", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("fp.js: status %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("FingerprintJS")) {
		t.Error("served bundle does not look like FingerprintJS")
	}
}

// newTestMAC mirrors the production HMAC construction for building legacy
// cookies in tests without exporting internals.
func newTestMAC(secret, input string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprint(mac, input)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// TestBypassCookieSecureFlag checks the bypass cookie carries the Secure flag
// exactly when the solve arrived over TLS (directly or via a trusted
// TLS-terminating proxy's X-Forwarded-Proto), and never on plain HTTP.
func TestBypassCookieSecureFlag(t *testing.T) {
	c := New("secret", 3600, 5)

	solve := func(mutate func(*http.Request)) *http.Cookie {
		t.Helper()
		nonce := "74657374"
		exp := time.Now().Unix() + 120
		body, _ := json.Marshal(map[string]any{
			"nonce":    nonce,
			"exp":      exp,
			"sig":      c.signNonce(nonce, exp),
			"solution": solvePoW(nonce),
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/_cz/verify", bytes.NewReader(body))
		mutate(req)
		c.ServeVerify(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("verify returned %d: %s", rec.Code, rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("expected 1 cookie, got %d", len(cookies))
		}
		return cookies[0]
	}

	if ck := solve(func(r *http.Request) {}); ck.Secure {
		t.Error("plain-HTTP solve issued a Secure cookie — browsers would drop it")
	}
	if ck := solve(func(r *http.Request) { r.TLS = &tls.ConnectionState{} }); !ck.Secure {
		t.Error("TLS solve issued a cookie without the Secure flag")
	}
	if ck := solve(func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }); !ck.Secure {
		t.Error("X-Forwarded-Proto https solve issued a cookie without the Secure flag")
	}
}
