package waf

import (
	"bytes"
	"io"
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
}
