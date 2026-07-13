package services

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/storage"
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

// TestPrefixMatch pins the path-segment boundary contract: "/api" must not
// match "/apiary" or "/api-v2", trailing slashes on the configured prefix
// are tolerated, and stripping returns a rooted path.
func TestPrefixMatch(t *testing.T) {
	cases := []struct {
		path, prefix string
		match        bool
		stripped     string
	}{
		{"/api", "/api", true, "/"},
		{"/api/", "/api", true, "/"},
		{"/api/users", "/api", true, "/users"},
		{"/apiary", "/api", false, "/apiary"},
		{"/api-v2/users", "/api", false, "/api-v2/users"},
		{"/api/users", "/api/", true, "/users"},
		{"/apiary", "/api/", false, "/apiary"},
		{"/anything", "/", true, "/anything"},
		{"/", "/", true, "/"},
	}
	for _, tc := range cases {
		if got := PrefixMatch(tc.path, tc.prefix); got != tc.match {
			t.Errorf("PrefixMatch(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.match)
		}
		if got := StripPrefix(tc.path, tc.prefix); got != tc.stripped {
			t.Errorf("StripPrefix(%q, %q) = %q, want %q", tc.path, tc.prefix, got, tc.stripped)
		}
	}
}

// TestRegistryMatchPrefixBoundary routes through a real registry: a path
// that merely shares leading bytes with a prefix service must fall through
// to the host service instead of being misrouted to the prefix backend.
func TestRegistryMatchPrefixBoundary(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddService("site", "www.example.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddService("api", "", "/api", "http://10.0.0.6:4000", 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path string
		want string
	}{
		{"/api", "api"},
		{"/api/users", "api"},
		{"/apiary", "site"},
		{"/api-v2/users", "site"},
		{"/", "site"},
	}
	for _, tc := range cases {
		got := reg.Match("www.example.com", tc.path)
		if got == nil || got.Name != tc.want {
			name := "<nil>"
			if got != nil {
				name = got.Name
			}
			t.Errorf("Match(%q) = %s, want %s", tc.path, name, tc.want)
		}
	}
}

// TestRegistryMatchUnmatchedHostReturnsNil covers the fix for a reported
// bug: hitting this server on a Host nothing is configured for (e.g. its
// bare listen IP, instead of a service's domain) used to silently fall back
// to the first configured service — so that service's backend received,
// and its name appeared in the logs for, traffic that had nothing to do
// with it. Match must return nil instead, regardless of registration
// order, as long as no Prefix or Host actually matches.
func TestRegistryMatchUnmatchedHostReturnsNil(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddService("example-api", "example-api.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddService("example-fe", "example-fe.com", "", "http://10.0.0.6:4000", 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"192.168.1.1", "203.0.113.7", "some-other-domain.com"} {
		if got := reg.Match(host, "/"); got != nil {
			t.Errorf("Match(%q, \"/\") = %s, want nil (first-service fallback should not apply)", host, got.Name)
		}
	}

	// Sanity check: the services' own hosts still resolve correctly —
	// removing the fallback must not break real routing.
	if got := reg.Match("example-api.com", "/"); got == nil || got.Name != "example-api" {
		t.Fatalf("Match(\"example-api.com\") did not resolve to the matching service")
	}
	if got := reg.Match("example-fe.com", "/"); got == nil || got.Name != "example-fe" {
		t.Fatalf("Match(\"example-fe.com\") did not resolve to the matching service")
	}
}

// TestRegistryIsServiceHost covers the admin-dashboard-hijack fix: the
// hostGuard middleware (internal/ui) uses this to keep /admin/* from being
// served on a service's own domain, so it must accurately say which hosts
// are claimed — case-insensitively, with any port ignored, and never for a
// service that only has a Prefix rule (those aren't host-specific).
func TestRegistryIsServiceHost(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddService("example-api", "Example-API.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.AddService("prefix-only", "", "/api", "http://10.0.0.6:4000", 0, 0); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"example-api.com", true},
		{"EXAMPLE-API.COM", true},
		{"example-api.com:8443", true},
		{"192.168.1.1", false},
		{"unrelated-domain.com", false},
	}
	for _, tc := range cases {
		if got := reg.IsServiceHost(tc.host); got != tc.want {
			t.Errorf("IsServiceHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}

	var nilReg *Registry
	if nilReg.IsServiceHost("anything") {
		t.Error("IsServiceHost on a nil *Registry must return false, not panic")
	}
}

// TestValidateRejectsMetadataEndpoints checks the go/request-forgery
// mitigation: admin-supplied backend URLs pointing at a cloud
// instance-metadata endpoint are rejected before Probe ever contacts them,
// while ordinary internal/private backends (the expected, legitimate use of
// this field) are left alone.
func TestValidateRejectsMetadataEndpoints(t *testing.T) {
	cases := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"aws/azure/gcp/do metadata IP", "http://169.254.169.254/latest/meta-data/", true},
		{"metadata IP with port", "http://169.254.169.254:80/", true},
		{"gcp metadata hostname", "http://metadata.google.internal/computeMetadata/v1/", true},
		{"gcp metadata hostname mixed case", "http://Metadata.Google.Internal/", true},
		{"aws imds v2 ipv6", "http://[fd00:ec2::254]/latest/meta-data/", true},
		{"ordinary loopback backend", "http://127.0.0.1:3000", false},
		{"ordinary private network backend", "http://10.0.0.5:8080", false},
		{"ordinary public backend", "http://198.51.100.1", false}, // RFC 5737 documentation range, no real DNS lookup
		{"missing scheme", "example.com", true},
		{"missing host", "http://", true},
		{"unparseable", "http://[::1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.backend)
			if tc.wantErr && err == nil {
				t.Errorf("Validate(%q) = nil, want error", tc.backend)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tc.backend, err)
			}
		})
	}
}
