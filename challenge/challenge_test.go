package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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
