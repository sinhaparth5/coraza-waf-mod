package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/proxy"
	"coraza-waf-mod/internal/security/adaptive"
	"coraza-waf-mod/internal/security/blocklist"
	"coraza-waf-mod/internal/security/challenge"
	"coraza-waf-mod/internal/security/geo"
	"coraza-waf-mod/internal/security/ratelimit"
	"coraza-waf-mod/internal/security/threatscore"
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

	return proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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

// TestPerServiceWAFException confirms a rule exception scoped to one service
// (911100, "Method is not allowed by policy" — CRS's default allowed_methods
// excludes PATCH/PUT/DELETE) only applies to that service's requests; a
// different service sharing the same WAF still gets blocked by the rule.
func TestPerServiceWAFException(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := db.AddService("open-svc", "", "/open", backend.URL, 0, 0); err != nil {
		t.Fatalf("add open-svc: %v", err)
	}
	if err := db.AddService("restricted-svc", "", "/restricted", backend.URL, 0, 0); err != nil {
		t.Fatalf("add restricted-svc: %v", err)
	}

	reg, err := services.New(db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	defaultEngine, err := waf.New(config.WAFConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("default waf init: %v", err)
	}
	openEngine, err := waf.New(config.WAFConfig{Enabled: true}, []int{911100})
	if err != nil {
		t.Fatalf("open-svc waf init: %v", err)
	}
	wafByService := map[string]*waf.Engine{"open-svc": openEngine}

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		t.Fatalf("ipbl: %v", err)
	}
	geoBl, err := geo.New("", db)
	if err != nil {
		t.Fatalf("geo: %v", err)
	}
	defer geoBl.Close()
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h := proxy.NewHandler(reg, defaultEngine, wafByService, db, ipbl, geoBl, rl, nil, nil, nil, nil)
	e := echo.New()

	req := httptest.NewRequest(http.MethodPatch, "/open/posts/1", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("open-svc PATCH: expected 200 (911100 disabled for this service), got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPatch, "/restricted/posts/1", nil)
	req2.Header.Set("X-Real-IP", "1.2.3.4")
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)
	_ = h.Handle(c2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("restricted-svc PATCH: expected 403 (911100 still enforced globally), got %d", rec2.Code)
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

	h2 := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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
	h2 := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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

	h2 := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil, "198.51.100.0/24")
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

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
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

// TestAdaptiveEnforcementTightensRateLimitForHighRiskIP exercises issue #16
// end to end: a client whose cached threat score is at/above the configured
// high-risk threshold gets a scaled-down effective rate limit, while an
// unscored client keeps the normal limit.
func TestAdaptiveEnforcementTightensRateLimitForHighRiskIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "adaptive-rl.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.AddService("svc", "", "/", backend.URL, 0, 0); err != nil {
		t.Fatalf("add service: %v", err)
	}

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)

	// Generous global limit (burst 10) so an unscored IP sails through a
	// handful of requests; the point is the high-risk IP getting a much
	// smaller *effective* burst via adaptive scaling.
	rl := ratelimit.New(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 10})
	defer rl.Stop()

	scorer := threatscore.New(db, func(string) int { return 100 }) // autoban part clamps to 40
	defer scorer.Stop()
	// Seed the cache directly (Record normally runs async off the log
	// worker) so CurrentScore reflects a high score before any request.
	scorer.Record(storage.RequestLog{RealIP: "203.0.113.50", BotScore: 100}) // 40 + 20 = 60

	if err := db.SetAdaptiveEnforcementConfig(storage.AdaptiveEnforcementConfig{
		Enabled: true, HighRiskThreshold: 50, LowRiskThreshold: 0,
		HighRiskRateScale: 0.2, LowRiskRateScale: 1.0, ForceChallengeThreshold: 100,
	}); err != nil {
		t.Fatal(err)
	}
	adaptivePolicy := adaptive.New(db)

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, scorer, adaptivePolicy)
	e := echo.New()

	sendReq := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// X-Real-IP is only honored from a trusted proxy (none configured
		// here) — set RemoteAddr directly, matching TestIPBlockedByRule.
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		return rec.Code
	}

	// High-risk IP: effective burst floor(10*0.2)=2. 3rd request must block.
	if code := sendReq("203.0.113.50"); code != http.StatusOK {
		t.Fatalf("high-risk IP request 1 = %d, want 200", code)
	}
	if code := sendReq("203.0.113.50"); code != http.StatusOK {
		t.Fatalf("high-risk IP request 2 = %d, want 200", code)
	}
	if code := sendReq("203.0.113.50"); code != http.StatusTooManyRequests {
		t.Fatalf("high-risk IP request 3 = %d, want 429 (scaled burst 2 exhausted)", code)
	}

	// Unscored IP: normal burst of 10 comfortably covers 3 requests.
	for i := 1; i <= 3; i++ {
		if code := sendReq("203.0.113.51"); code != http.StatusOK {
			t.Fatalf("unscored IP request %d = %d, want 200 (normal burst 10)", i, code)
		}
	}
}

// TestAdaptiveEnforcementForcesChallengeForHighRiskIP checks a client whose
// score meets ForceChallengeThreshold is redirected to the challenge page
// even though the per-service bot_mode is "inherit" and the request's own
// bot-analysis score never crosses the challenger's own threshold.
func TestAdaptiveEnforcementForcesChallengeForHighRiskIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "adaptive-challenge.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.AddService("svc", "", "/", backend.URL, 0, 0); err != nil {
		t.Fatalf("add service: %v", err)
	}

	ipbl, _ := blocklist.NewIPBlocklist(db)
	geoBl, _ := geo.New("", db)
	defer geoBl.Close()
	reg, _ := services.New(db)
	engine, _ := waf.New(config.WAFConfig{Enabled: false}, nil)
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	scorer := threatscore.New(db, func(string) int { return 100 })
	defer scorer.Stop()
	scorer.Record(storage.RequestLog{RealIP: "203.0.113.60", BotScore: 100}) // 40 + 20 = 60
	scorer.Record(storage.RequestLog{RealIP: "203.0.113.61", BotScore: 0})   // 0 — normal

	if err := db.SetAdaptiveEnforcementConfig(storage.AdaptiveEnforcementConfig{
		Enabled: true, HighRiskThreshold: 50, LowRiskThreshold: 0,
		HighRiskRateScale: 1.0, LowRiskRateScale: 1.0, ForceChallengeThreshold: 50,
	}); err != nil {
		t.Fatal(err)
	}
	adaptivePolicy := adaptive.New(db)

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, scorer, adaptivePolicy)
	// Threshold 1000: botAnalysis's own score can never trigger a challenge
	// on its own — only the adaptive policy can, isolating what this test
	// actually proves.
	h.ReloadBotProtection(challenge.New("test-secret", 3600, 1000))
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// X-Real-IP is only honored from a trusted proxy (none configured here).
	req.RemoteAddr = "203.0.113.60:12345"
	rec := httptest.NewRecorder()
	_ = h.Handle(e.NewContext(req, rec))
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("high-risk IP: expected 307 challenge redirect, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.61:12345"
	rec = httptest.NewRecorder()
	_ = h.Handle(e.NewContext(req, rec))
	if rec.Code != http.StatusOK {
		t.Fatalf("normal-risk IP: expected 200 (proxied, no challenge), got %d", rec.Code)
	}
}
