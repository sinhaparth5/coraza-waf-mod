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

// TestCheckBodyOverLimit sends a multipart body one byte past
// SecRequestBodyLimit through a counting reader: Coraza must reject it (413,
// the recommended config's SecRequestBodyLimitAction) while Check reads at
// most limit+1 bytes into memory instead of buffering the whole upload.
func TestCheckBodyOverLimit(t *testing.T) {
	e := newTestEngine(t)

	over := requestBodyLimit + 10
	cr := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), over))}
	r := httptest.NewRequest("POST", "http://app.example.com/upload", cr)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
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

// TestInspectionFor pins the content-type gate down as data. The split that
// matters: multipart carries file parts Coraza routes away from ARGS and is
// cheap at megabytes, every other inspectable type is parsed into ARGS in full
// and is not, and a binary type is not inspected at all.
func TestInspectionFor(t *testing.T) {
	for _, tc := range []struct {
		contentType string
		want        bodyInspection
	}{
		{"application/x-www-form-urlencoded", inspectNoFiles},
		{"application/json", inspectNoFiles},
		{"application/json; charset=utf-8", inspectNoFiles},
		{"APPLICATION/JSON", inspectNoFiles},
		{"  application/json  ", inspectNoFiles},
		{"application/vnd.api+json", inspectNoFiles},
		{"application/soap+xml", inspectNoFiles},
		{"application/xml", inspectNoFiles},
		{"text/plain", inspectNoFiles},
		{"text/html; charset=utf-8", inspectNoFiles},
		{"", inspectNoFiles},
		{"multipart/form-data; boundary=xyz", inspectFiles},
		{"multipart/related", inspectFiles},
		{"application/pdf", inspectSkip},
		{"application/octet-stream", inspectSkip},
		{"image/png", inspectSkip},
		{"video/mp4", inspectSkip},
		{"application/zip", inspectSkip},
	} {
		if got := inspectionFor(tc.contentType); got != tc.want {
			t.Errorf("inspectionFor(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}

// TestCheckStreamsUninspectableBody is the fix for the memory blow-up: a
// binary upload must reach the backend without this process reading it. The
// counting reader proves Check never pulled a byte off the wire, and the body
// must still be forwardable in full afterwards.
func TestCheckStreamsUninspectableBody(t *testing.T) {
	// CRS scores the request line itself here — 911100 rejects PUT (its
	// allowed-methods policy is GET/HEAD/POST/OPTIONS) and 920420 rejects a
	// content type outside its allow-list — and either alone crosses the
	// inbound anomaly threshold. Both are header-phase policy an operator
	// tunes per service; excluding them is what leaves this test asserting
	// the one thing the gate is responsible for, the body.
	e, err := New(config.WAFConfig{Enabled: true}, []int{911100, 920420})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	payload := bytes.Repeat([]byte("\x00\x01binary&payload=here&"), 4096)
	cr := &countingReader{r: bytes.NewReader(payload)}
	r := httptest.NewRequest("PUT", "http://app.example.com/upload?key=notes.pdf", cr)
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if cr.n != 0 {
		t.Errorf("check read %d bytes of an uninspectable body, want 0 (it must stream)", cr.n)
	}
	if res.Blocked {
		t.Errorf("binary upload blocked by body inspection that should not have run: %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Errorf("body after check = %d bytes (err %v), want the original %d intact", len(got), err, len(payload))
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Errorf("uninspected body must never be cached, got %d cache entries", got)
	}
}

// TestCheckNoFilesBodyOverLimit covers the limit Coraza parses and ignores
// (corazawaf/coraza#896): a non-multipart body past noFilesBodyLimit is
// refused here rather than parsed into ARGS, and the wire read stops at the
// limit instead of buffering the whole thing.
func TestCheckNoFilesBodyOverLimit(t *testing.T) {
	e := newTestEngine(t)

	over := noFilesBodyLimit + 10
	cr := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), over))}
	r := httptest.NewRequest("POST", "http://app.example.com/api", cr)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Blocked || res.Status != 413 {
		t.Errorf("over-limit no-files body: blocked=%v status=%d, want blocked with 413", res.Blocked, res.Status)
	}
	if cr.n > noFilesBodyLimit+1 {
		t.Errorf("check read %d bytes off the wire, want at most limit+1 (%d)", cr.n, noFilesBodyLimit+1)
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Errorf("over-limit request must never be cached, got %d cache entries", got)
	}
}

// TestCheckNoFilesBodyAtLimit is the boundary the test above does not cover:
// exactly at the limit is inspected normally, not refused.
func TestCheckNoFilesBodyAtLimit(t *testing.T) {
	e := newTestEngine(t)

	payload := bytes.Repeat([]byte("a"), noFilesBodyLimit)
	r := httptest.NewRequest("POST", "http://app.example.com/api", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked && res.Status == 413 {
		t.Errorf("body exactly at the limit was refused as over-limit: %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || len(got) != len(payload) {
		t.Errorf("body after check = %d bytes (err %v), want %d intact", len(got), err, len(payload))
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
