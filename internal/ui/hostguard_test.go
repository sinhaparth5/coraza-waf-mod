package ui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

// TestHostGuardBlocksAdminOnServiceDomain reproduces a reported bug: with a
// service configured for "example-api.com", requesting
// "example-api.com/admin/login" opened the WAF's own admin login page,
// because Echo's router matches routes purely by path with no notion of
// Host — the admin group had no way to tell it wasn't being reached via the
// server's own management address. hostGuard must hand any request whose
// Host matches a configured service straight to the reverse-proxy pipeline
// instead, and must leave the admin UI reachable on any Host nothing
// claims (e.g. the server's bare listen IP).
func TestHostGuardBlocksAdminOnServiceDomain(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.AddService("example-api", "example-api.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}

	var proxiedHost string
	proxyCalls := 0
	h := &Handler{
		cfg:        &config.Config{Admin: config.AdminConfig{Path: "/admin"}},
		db:         db,
		registry:   reg,
		staticJS:   fstest.MapFS{},
		staticImgs: fstest.MapFS{},
		proxyHandle: func(c echo.Context) error {
			proxyCalls++
			proxiedHost = c.Request().Host
			return c.NoContent(http.StatusTeapot) // distinct sentinel status
		},
	}
	if err := h.parseTemplates(); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	h.Register(e)

	// The bug: hitting the admin login path on a configured service's own
	// domain must not open the dashboard.
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.Host = "example-api.com"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("GET /admin/login on a service's own domain = %d, want %d (should be handed to the proxy, not served the admin login page)", rec.Code, http.StatusTeapot)
	}
	if proxyCalls != 1 || proxiedHost != "example-api.com" {
		t.Fatalf("proxyHandle called %d time(s) for host %q, want exactly once for example-api.com", proxyCalls, proxiedHost)
	}

	// The fix must not break the admin UI on a Host nothing claims — e.g.
	// this server's bare listen IP.
	req = httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.Host = "192.168.1.1"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/login on the server's own IP = %d, want 200 (admin login page)", rec.Code)
	}
	if proxyCalls != 1 {
		t.Fatalf("proxyHandle called %d time(s) after the second request, want still 1 (unclaimed host must not be proxied)", proxyCalls)
	}
}

// TestHostGuardBlocksAPIOnServiceDomain covers the same fix for the REST
// API group: it must be equally unreachable on a service's own domain.
func TestHostGuardBlocksAPIOnServiceDomain(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.AddService("example-api", "example-api.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}

	proxyCalls := 0
	h := &Handler{
		cfg:           &config.Config{Admin: config.AdminConfig{Path: "/admin"}},
		db:            db,
		registry:      reg,
		apiKeyLimiter: newLoginLimiter(),
		proxyHandle: func(c echo.Context) error {
			proxyCalls++
			return c.NoContent(http.StatusTeapot)
		},
	}
	e := echo.New()
	h.RegisterAPI(e)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/services", nil)
	req.Host = "example-api.com"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot || proxyCalls != 1 {
		t.Fatalf("GET /admin/api/v1/services on a service's own domain = %d (proxyCalls=%d), want %d via proxyHandle", rec.Code, proxyCalls, http.StatusTeapot)
	}

	// On an unclaimed host, the request must reach the normal API auth path
	// (401 for a missing bearer token) rather than the proxy.
	req = httptest.NewRequest(http.MethodGet, "/admin/api/v1/services", nil)
	req.Host = "192.168.1.1"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/api/v1/services on the server's own IP = %d, want 401 (normal apiKeyAuth path)", rec.Code)
	}
	if proxyCalls != 1 {
		t.Fatalf("proxyHandle called %d time(s) after the second request, want still 1", proxyCalls)
	}
}
