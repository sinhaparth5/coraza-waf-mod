package services

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"coraza-waf-mod/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestVarnishRouting covers the cache integration in Reload: a cache-enabled
// service is re-targeted at the local Varnish address with spoofable host
// headers scrubbed and the WAF↔Varnish contract headers set, while services
// without the flag (or with the integration globally off) proxy directly to
// their backend.
func TestVarnishRouting(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddService("cached", "cdn.example.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddService("direct", "app.example.com", "", "http://10.0.0.6:4000", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListServices()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list {
		if s.Name == "cached" {
			if err := db.SetServiceCache(s.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: "127.0.0.1:6081"}); err != nil {
		t.Fatal(err)
	}

	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}

	direct := func(name, path string) *http.Request {
		rp, ok := reg.Proxy(name)
		if !ok {
			t.Fatalf("no proxy for %q", name)
		}
		req := httptest.NewRequest(http.MethodGet, "http://cdn.example.com"+path, nil)
		// A malicious client trying to poison the cache key or spoof the
		// WAF↔Varnish contract headers.
		req.Header.Set("X-Forwarded-Host", "evil.example")
		req.Header.Set("X-Original-URL", "/admin")
		req.Header.Set("X-Cache-Service", "spoofed")
		req.Header.Set("X-Waf-Backend", "6.6.6.6:666")
		rp.Director(req)
		return req
	}

	req := direct("cached", "/logo.png")
	if req.URL.Scheme != "http" || req.URL.Host != "127.0.0.1:6081" {
		t.Errorf("cached service targeted %s://%s, want http://127.0.0.1:6081", req.URL.Scheme, req.URL.Host)
	}
	if req.URL.Path != "/logo.png" {
		t.Errorf("path = %q, want /logo.png", req.URL.Path)
	}
	if req.Host != "cdn.example.com" {
		t.Errorf("Host = %q, want the client host preserved for Varnish's hash", req.Host)
	}
	if got := req.Header.Get("X-Cache-Service"); got != "cached" {
		t.Errorf("X-Cache-Service = %q, want the real service name overriding the spoof", got)
	}
	if got := req.Header.Get("X-Waf-Backend"); got != "10.0.0.5:3000" {
		t.Errorf("X-Waf-Backend = %q, want 10.0.0.5:3000", got)
	}
	for _, hn := range []string{"X-Forwarded-Host", "X-Original-URL"} {
		if v := req.Header.Get(hn); v != "" {
			t.Errorf("%s = %q, want scrubbed before the cache layer", hn, v)
		}
	}

	req = direct("direct", "/index.html")
	if req.URL.Host != "10.0.0.6:4000" {
		t.Errorf("non-cache service targeted %s, want its backend 10.0.0.6:4000", req.URL.Host)
	}

	// Globally disabling the integration must point the cache-enabled service
	// back at its own backend on the next reload.
	if err := db.SetVarnishConfig(storage.VarnishConfig{Enabled: false, Addr: "127.0.0.1:6081"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(db); err != nil {
		t.Fatal(err)
	}
	req = direct("cached", "/logo.png")
	if req.URL.Host != "10.0.0.5:3000" {
		t.Errorf("with Varnish disabled, cached service targeted %s, want 10.0.0.5:3000", req.URL.Host)
	}
}

// TestCacheReturnHandler covers the loopback listener Varnish fetches misses
// from: routing by X-Cache-Service to the real backend with the path
// untouched, 404 for unknown service tags, and 403 for non-local peers.
func TestCacheReturnHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	db := openTestDB(t)
	if err := db.AddService("cached", "cdn.example.com", "", backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	h := reg.CacheReturnHandler()

	serve := func(remoteAddr, service string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://cdn.example.com/assets/app.js", nil)
		req.RemoteAddr = remoteAddr
		if service != "" {
			req.Header.Set("X-Cache-Service", service)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := serve("127.0.0.1:39000", "cached")
	if rec.Code != http.StatusOK || rec.Header().Get("X-Got-Path") != "/assets/app.js" {
		t.Errorf("miss fetch = %d (path %q), want 200 with the path forwarded untouched",
			rec.Code, rec.Header().Get("X-Got-Path"))
	}
	if got := rec.Header().Get("Server"); got != serverHeader {
		t.Errorf("Server = %q, want %q (ModifyResponse must run on the return hop)", got, serverHeader)
	}

	if rec := serve("127.0.0.1:39000", "nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown service tag = %d, want 404", rec.Code)
	}
	if rec := serve("127.0.0.1:39000", ""); rec.Code != http.StatusNotFound {
		t.Errorf("missing service tag = %d, want 404", rec.Code)
	}
	if rec := serve("192.0.2.1:1234", "cached"); rec.Code != http.StatusForbidden {
		t.Errorf("non-loopback peer = %d, want 403", rec.Code)
	}
}
