package proxy_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"palisade/internal/config"
	"palisade/internal/proxy"
	"palisade/internal/security/challenge"
	"palisade/internal/security/ratelimit"
	"palisade/internal/security/waf"

	"github.com/labstack/echo/v4"
)

func TestChallengeRoutesFollowReload(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	h := newTestHandler(t, backend)

	serve := func(fn func(http.ResponseWriter, *http.Request), method, path string) int {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	// Bot protection off: the routes exist but 404.
	for _, fn := range []func(http.ResponseWriter, *http.Request){h.ServeChallengePage, h.ServeChallengeVerify, h.ServeFingerprintJS} {
		if code := serve(fn, "GET", "/_cz/x"); code != http.StatusNotFound {
			t.Errorf("disabled challenger route = %d", code)
		}
	}
	h.ReloadBotProtection(challenge.New("secret", 3600, 5))
	// An unsigned query is the challenger's own 400, proving the route delegated.
	if code := serve(h.ServeChallengePage, "GET", "/_cz/challenge"); code != http.StatusBadRequest {
		t.Errorf("challenge page = %d", code)
	}
	if code := serve(h.ServeFingerprintJS, "GET", "/_cz/fp.js"); code != http.StatusOK {
		t.Errorf("fp.js = %d", code)
	}
	if code := serve(h.ServeChallengeVerify, "POST", "/_cz/verify"); code == http.StatusNotFound {
		t.Errorf("verify still 404 with challenger active")
	}
	h.ReloadBotProtection(nil)
	if code := serve(h.ServeChallengePage, "GET", "/_cz/challenge"); code != http.StatusNotFound {
		t.Errorf("challenge page after disable = %d", code)
	}
}

func TestReloadWAFAndRateLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	h := newTestHandler(t, backend)
	e := echo.New()
	get := func(path string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "203.0.113.9:1234"
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		return rec.Code
	}

	// Disabling the SQLi rule that fires on this payload via a reload lets it through.
	sqli := "/?id=1%27%20OR%20%271%27=%271"
	if code := get(sqli); code != http.StatusForbidden {
		t.Fatalf("baseline SQLi = %d", code)
	}
	off, err := waf.New(config.WAFConfig{Enabled: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.ReloadWAF(off, nil)
	if code := get(sqli); code != http.StatusOK {
		t.Errorf("after reload to a disabled engine = %d", code)
	}

	h.ReloadRateLimit(ratelimit.NewWithParams(1, 1))
	get("/a")
	if code := get("/b"); code != http.StatusTooManyRequests {
		t.Errorf("after rate-limit reload = %d", code)
	}
	h.ReloadRateLimit(nil)
	if code := get("/c"); code != http.StatusOK {
		t.Errorf("rate limit removed = %d", code)
	}
	h.StopRateLimit() // nil backend: no-op
	h.ReloadRateLimit(ratelimit.NewWithParams(1, 1))
	h.StopRateLimit()
}

func TestSecurityMiddlewareHeaders(t *testing.T) {
	e := echo.New()
	e.Use(proxy.SecurityMiddleware())
	e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy", "X-WAF-Engine"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain HTTP")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing over TLS")
	}
}

func TestTLSRequestLogged(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	h := newTestHandler(t, backend)
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "a.test"}
	rec := httptest.NewRecorder()
	if err := h.Handle(echo.New().NewContext(req, rec)); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("TLS request: %v %d", err, rec.Code)
	}
}
