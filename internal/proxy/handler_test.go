package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/proxy"
	"coraza-waf-mod/internal/security/blocklist"
	"coraza-waf-mod/internal/security/challenge"
	"coraza-waf-mod/internal/security/geo"
	"coraza-waf-mod/internal/security/ratelimit"
	"coraza-waf-mod/internal/security/waf"
	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

// newTestHandler builds a fully wired Handler backed by a temp SQLite DB and
// a real Coraza/CRS WAF engine. backend is used as the single proxied service.
func newTestHandler(t *testing.T, backend *httptest.Server) *proxy.Handler {
	t.Helper()

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.AddService("test-svc", "", "/", backend.URL, 0, 0); err != nil {
		t.Fatalf("add service: %v", err)
	}

	reg, err := services.New(db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	engine, err := waf.New(config.WAFConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("waf init: %v", err)
	}

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		t.Fatalf("ipbl: %v", err)
	}

	// Geo blocker with no DB path — uses bundled mmdb, blocks nothing by default.
	geoBl, err := geo.New("", db)
	if err != nil {
		t.Fatalf("geo: %v", err)
	}
	t.Cleanup(func() { geoBl.Close() })

	// Write a minimal GeoLite2 DB so the geo lookup doesn't fail on the
	// embedded copy path — it already embeds one, so no setup needed.
	_ = os.MkdirAll(filepath.Join(dir, "geo"), 0700)

	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	t.Cleanup(func() { rl.Stop() })

	return proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
}

func TestNormalRequestProxied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := newTestHandler(t, backend)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestSQLiBlockedByWAF(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // should never be reached
	}))
	defer backend.Close()

	h := newTestHandler(t, backend)
	e := echo.New()

	// Classic SQLi payload in the query string — CRS rules 942xxx cover this.
	req := httptest.NewRequest(http.MethodGet, "/?id=1'+OR+'1'='1", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	_ = h.Handle(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SQLi payload, got %d", rec.Code)
	}
}

func TestXSSBlockedByWAF(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := newTestHandler(t, backend)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, `/?q=<script>alert(1)</script>`, nil)
	req.Header.Set("X-Real-IP", "5.6.7.8")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	_ = h.Handle(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for XSS payload, got %d", rec.Code)
	}
}

func TestIPBlocklistBlocks(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Block 10.0.0.1 globally — build a fresh handler with a real IP rule.
	dir := t.TempDir()
	db, _ := storage.Open(filepath.Join(dir, "bl.db"))
	defer db.Close()
	_ = db.AddService("svc", "", "/", backend.URL, 0, 0)
	_ = db.AddIPRule("", "10.0.0.1", "block")

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h2 := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	_ = h2.Handle(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("blocked IP should get 403, got %d", rec.Code)
	}
}

func TestRateLimitReturns429(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, _ := storage.Open(filepath.Join(dir, "rl.db"))
	defer db.Close()
	_ = db.AddService("svc", "", "/", backend.URL, 0, 0)

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)

	// 1 req/s, burst 1 — second request from same IP must be throttled.
	rl := ratelimit.New(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})
	defer rl.Stop()

	h := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
	e := echo.New()

	sendReq := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "9.9.9.9")
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		return rec.Code
	}

	sendReq() // consumes burst
	if code := sendReq(); code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after burst exhausted, got %d", code)
	}
}

func TestCFConnectingIPUsedAsRealIP(t *testing.T) {
	var capturedRemote string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The proxy strips CF-Connecting-IP from the upstream request, but we
		// verify the block decision uses it by blocking 203.0.113.1 in the blocklist.
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, _ := storage.Open(filepath.Join(dir, "cf.db"))
	defer db.Close()
	_ = db.AddService("svc", "", "/", backend.URL, 0, 0)
	_ = db.AddIPRule("", "203.0.113.1", "block")

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	_ = capturedRemote
	h2 := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// RemoteAddr is a CDN edge IP; real client IP is in CF-Connecting-IP.
	req.RemoteAddr = "104.18.0.1:443"
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	_ = h2.Handle(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("CF-Connecting-IP should be used as real IP for blocklist check, got %d", rec.Code)
	}
}

func TestCFConnectingIPSpoofIgnored(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, _ := storage.Open(filepath.Join(dir, "spoof.db"))
	defer db.Close()
	_ = db.AddService("svc", "", "/", backend.URL, 0, 0)
	// Block the IP the attacker tries to impersonate via the spoofed header.
	_ = db.AddIPRule("", "203.0.113.1", "block")

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h2 := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// RemoteAddr is NOT a Cloudflare IP — direct-to-origin connection.
	req.RemoteAddr = "198.51.100.5:12345"
	// Attacker sets CF-Connecting-IP trying to appear as a blocked IP or hide their own.
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")
	rec := httptest.NewRecorder()

	c := e.NewContext(req, rec)
	_ = h2.Handle(c)

	// The spoofed header must be ignored; real IP 198.51.100.5 is not blocked → 200.
	if rec.Code != http.StatusOK {
		t.Errorf("spoofed CF-Connecting-IP should be ignored, expected 200 got %d", rec.Code)
	}
}

func TestForwardedHeadersIgnoredFromUntrustedSource(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, _ := storage.Open(filepath.Join(dir, "xff-spoof.db"))
	defer db.Close()
	_ = db.AddService("svc", "", "/", backend.URL, 0, 0)
	_ = db.AddIPRule("", "203.0.113.10", "block")

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.5:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	rec := httptest.NewRecorder()

	_ = h.Handle(e.NewContext(req, rec))

	if rec.Code != http.StatusOK {
		t.Errorf("untrusted forwarded headers should be ignored, expected 200 got %d", rec.Code)
	}
}

func TestForwardedHeadersUsedFromTrustedProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, _ := storage.Open(filepath.Join(dir, "xff-trusted.db"))
	defer db.Close()
	_ = db.AddService("svc", "", "/", backend.URL, 0, 0)
	_ = db.AddIPRule("", "203.0.113.10", "block")

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil, "198.51.100.0/24")
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.5:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.5")
	rec := httptest.NewRecorder()

	_ = h.Handle(e.NewContext(req, rec))

	if rec.Code != http.StatusForbidden {
		t.Errorf("trusted X-Forwarded-For should be used for blocklist check, got %d", rec.Code)
	}
}

func TestRateLimitHeadersPresent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "hdrs.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.AddService("svc", "", "/", backend.URL, 5, 10); err != nil {
		t.Fatalf("add service: %v", err)
	}

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h := proxy.NewHandler(reg, engine, db, ipbl, geoBl, rl, nil, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "7.7.7.7")
	rec := httptest.NewRecorder()
	_ = h.Handle(e.NewContext(req, rec))

	if rec.Header().Get("CZ-RateLimit-Limit") == "" {
		t.Error("CZ-RateLimit-Limit header missing on rate-limited service response")
	}
	if rec.Header().Get("CZ-RateLimit-Remaining") == "" {
		t.Error("CZ-RateLimit-Remaining header missing")
	}
}

// A /_cz/* request that reaches the catch-all (an unregistered method/path,
// e.g. HEAD /_cz/challenge — only GET is routed to the challenge page) must
// 404, never redirect back to the challenge: that 307 points at /_cz/challenge
// itself, looping the client forever.
func TestChallengeNamespaceNeverChallengedOrProxied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // should never be reached
	}))
	defer backend.Close()

	h := newTestHandler(t, backend)
	// Threshold 0 = every non-trusted client is challenged, so without the
	// /_cz/ guard this request would 307.
	h.ReloadBotProtection(challenge.New("test-secret", 3600, 0))
	e := echo.New()

	req := httptest.NewRequest(http.MethodHead, "/_cz/challenge", nil)
	req.Header.Set("X-Real-IP", "198.23.130.204")
	rec := httptest.NewRecorder()
	if err := h.Handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("HEAD /_cz/challenge: expected 404, got %d (Location: %q)", rec.Code, rec.Header().Get("Location"))
	}

	// Sanity check the challenger is actually live: a normal path still 307s.
	req = httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req.Header.Set("X-Real-IP", "198.23.130.204")
	rec = httptest.NewRecorder()
	_ = h.Handle(e.NewContext(req, rec))
	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("normal path with active challenger: expected 307, got %d", rec.Code)
	}
}
