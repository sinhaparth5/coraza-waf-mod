package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

func TestProbes(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	registerProbes(e, db)
	e.Any("/*", func(c echo.Context) error { return c.String(http.StatusTeapot, "proxied") })

	get := func(method, path string) int {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if c := get(m, "/_cz/healthz"); c != http.StatusOK {
			t.Errorf("%s healthz = %d, want 200", m, c)
		}
		if c := get(m, "/_cz/readyz"); c != http.StatusOK {
			t.Errorf("%s readyz = %d, want 200", m, c)
		}
	}
	db.Close()
	if c := get(http.MethodGet, "/_cz/readyz"); c != http.StatusServiceUnavailable {
		t.Errorf("readyz with DB closed = %d, want 503", c)
	}
	if c := get(http.MethodGet, "/_cz/healthz"); c != http.StatusOK {
		t.Errorf("healthz with DB closed = %d, want 200 (liveness ignores the DB)", c)
	}
}
