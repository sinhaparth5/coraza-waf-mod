package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"coraza-waf-mod/internal/config"
)

// countingReader tracks how many bytes Check actually pulls off the wire, so
// the tests can prove an over-limit upload is never fully buffered.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(config.WAFConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	return e
}

// TestCheckBodyBuffered covers the normal case: an in-limit body passes the
// WAF and is fully replayable afterwards so the proxy can forward it.
func TestCheckBodyBuffered(t *testing.T) {
	e := newTestEngine(t)

	const payload = "greeting=hello"
	r := httptest.NewRequest("POST", "http://app.example.com/submit", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked {
		t.Fatalf("benign body blocked: %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != payload {
		t.Errorf("body after check = %q, %v; want %q intact", got, err, payload)
	}
}

// TestCheckBodyOverLimit sends a body one byte past SecRequestBodyLimit
// through a counting reader: Coraza must reject it (413, the recommended
// config's SecRequestBodyLimitAction) while Check reads at most limit+1
// bytes into memory instead of buffering the whole upload.
func TestCheckBodyOverLimit(t *testing.T) {
	e := newTestEngine(t)

	over := requestBodyLimit + 10
	cr := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), over))}
	r := httptest.NewRequest("POST", "http://app.example.com/upload", cr)
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Blocked || res.Status != 413 {
		t.Errorf("over-limit body: blocked=%v status=%d, want blocked with 413", res.Blocked, res.Status)
	}
	if cr.n > requestBodyLimit+1 {
		t.Errorf("check read %d bytes off the wire, want at most limit+1 (%d)", cr.n, requestBodyLimit+1)
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Errorf("over-limit request must never be cached, got %d cache entries", got)
	}
}

// TestCheckDeduplicatesIdenticalRequests proves the verdict cache (issue #13)
// actually keys on the request fingerprint: a byte-identical repeat reuses
// the existing cache entry instead of creating a new one, while a request
// that differs only in query string gets its own entry.
func TestCheckDeduplicatesIdenticalRequests(t *testing.T) {
	e := newTestEngine(t)

	newReq := func(query string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/search?"+query, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Accept", "*/*")
		return r
	}

	if _, err := e.Check(newReq("q=hello"), "203.0.113.9"); err != nil {
		t.Fatalf("check 1: %v", err)
	}
	if got := e.cache.order.Len(); got != 1 {
		t.Fatalf("cache entries after 1st request = %d, want 1", got)
	}

	if _, err := e.Check(newReq("q=hello"), "203.0.113.9"); err != nil {
		t.Fatalf("check 2 (identical repeat): %v", err)
	}
	if got := e.cache.order.Len(); got != 1 {
		t.Fatalf("cache entries after identical repeat = %d, want 1 (should reuse the existing entry)", got)
	}

	if _, err := e.Check(newReq("q=different"), "203.0.113.9"); err != nil {
		t.Fatalf("check 3 (distinct query): %v", err)
	}
	if got := e.cache.order.Len(); got != 2 {
		t.Fatalf("cache entries after distinct request = %d, want 2", got)
	}
}

// TestCheckNeverCachesCookieOrAuthRequests proves requests carrying a
// session cookie or Authorization header are excluded from the verdict
// cache entirely (issue #13's identity-safety requirement) — a
// method+path+query+body fingerprint doesn't capture "which logged-in user."
func TestCheckNeverCachesCookieOrAuthRequests(t *testing.T) {
	e := newTestEngine(t)

	withCookie := httptest.NewRequest("GET", "http://app.example.com/account", nil)
	withCookie.Header.Set("User-Agent", "Mozilla/5.0")
	withCookie.Header.Set("Cookie", "session=abc123")
	if _, err := e.Check(withCookie, "203.0.113.9"); err != nil {
		t.Fatalf("check (cookie): %v", err)
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Fatalf("cache entries after cookie-bearing request = %d, want 0", got)
	}

	withAuth := httptest.NewRequest("GET", "http://app.example.com/api", nil)
	withAuth.Header.Set("Authorization", "Bearer abc123")
	if _, err := e.Check(withAuth, "203.0.113.9"); err != nil {
		t.Fatalf("check (authorization): %v", err)
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Fatalf("cache entries after Authorization-bearing request = %d, want 0", got)
	}
}
