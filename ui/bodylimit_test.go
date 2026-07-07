package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"coraza-waf-mod/config"

	"github.com/labstack/echo/v4"
)

// TestAdminBodyLimit checks the 1 MiB body cap is wired onto both the
// unauthenticated login POST and the admin group, and that it fires before
// session auth (413, not a login redirect) — the WAF's SecRequestBodyLimit
// never covers these routes, so this middleware is the only guard.
func TestAdminBodyLimit(t *testing.T) {
	e := echo.New()
	h := &Handler{
		cfg:          config.Defaults(),
		loginLimiter: newLoginLimiter(),
		staticJS:     fstest.MapFS{},
		staticImgs:   fstest.MapFS{},
	}
	h.Register(e)

	big := strings.NewReader(strings.Repeat("a", 2<<20)) // 2 MiB

	req := httptest.NewRequest(http.MethodPost, "/admin/login", big)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized login POST = %d, want 413", rec.Code)
	}

	big.Seek(0, 0) //nolint:errcheck
	req = httptest.NewRequest(http.MethodPost, "/admin/ip-rules", big)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized admin POST = %d, want 413 before auth redirect", rec.Code)
	}
}
