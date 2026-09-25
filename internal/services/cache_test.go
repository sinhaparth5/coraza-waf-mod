package services

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"coraza-waf-mod/internal/storage"
)

func TestStaleCacheServices(t *testing.T) {
	svc := func(name, backend, host, prefix string) storage.Service {
		return storage.Service{Name: name, Backend: backend, Host: host, Prefix: prefix}
	}
	a := svc("a", "http://10.0.0.1", "a.com", "")
	b := svc("b", "http://10.0.0.2", "", "/b")
	cases := []struct {
		name      string
		old       []storage.Service
		oldCached map[string]bool
		new       []storage.Service
		newCached map[string]bool
		want      []string
	}{
		{"unchanged", []storage.Service{a, b}, map[string]bool{"a": true, "b": true}, []storage.Service{a, b}, map[string]bool{"a": true, "b": true}, nil},
		{"removed", []storage.Service{a, b}, map[string]bool{"a": true, "b": true}, []storage.Service{b}, map[string]bool{"b": true}, []string{"a"}},
		{"cache turned off", []storage.Service{a}, map[string]bool{"a": true}, []storage.Service{a}, map[string]bool{}, []string{"a"}},
		{"backend changed", []storage.Service{a}, map[string]bool{"a": true}, []storage.Service{svc("a", "http://10.0.0.9", "a.com", "")}, map[string]bool{"a": true}, []string{"a"}},
		{"host changed", []storage.Service{a}, map[string]bool{"a": true}, []storage.Service{svc("a", "http://10.0.0.1", "new.com", "")}, map[string]bool{"a": true}, []string{"a"}},
		{"prefix changed", []storage.Service{b}, map[string]bool{"b": true}, []storage.Service{svc("b", "http://10.0.0.2", "", "/c")}, map[string]bool{"b": true}, []string{"b"}},
		{"was never cached", []storage.Service{a}, map[string]bool{}, nil, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := staleCacheServices(tc.old, tc.oldCached, tc.new, tc.newCached)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPurgeURLRegex(t *testing.T) {
	cases := []struct {
		prefix, backend, path, want string
	}{
		{"", "http://10.0.0.1:3000", "/blog/", "^/blog/"},
		{"", "http://10.0.0.1:3000/base/", "/blog/", "^/base/blog/"},
		{"/blog", "http://10.0.0.1:3000", "/blog/posts", "^/posts"},
		{"/blog", "http://10.0.0.1:3000/base", "/blog", "^/base/"},
		{"/blog", "http://10.0.0.1:3000", "/other", "^/other"},
		{"", "http://10.0.0.1:3000", "/app.min.js", "^/app[.]min[.]js"},
	}
	for _, tc := range cases {
		svc := storage.Service{Prefix: tc.prefix, Backend: tc.backend}
		if got := purgeRegex(backendURLPath(svc, tc.path)); got != tc.want {
			t.Errorf("prefix=%q backend=%q path=%q: got %q, want %q", tc.prefix, tc.backend, tc.path, got, tc.want)
		}
	}
}

func TestPurgeRejectsUnsafePath(t *testing.T) {
	vcfg := storage.VarnishConfig{Enabled: true, Addr: "127.0.0.1:1"}
	svc := storage.Service{Name: "shop", Backend: "http://10.0.0.1"}
	for _, p := range []string{"blog", "/a b", `/a"`, "/a&&obj.status", "/a||b", "/a\n"} {
		if err := Purge(vcfg, svc, p); err == nil || err.Error()[:4] != "path" {
			t.Errorf("Purge(%q) = %v, want path validation error", p, err)
		}
	}
}

// A cache-routed service must keep serving from its backend when varnishd is
// down, and not be marked unhealthy for Varnish's outage.
func TestVarnishDownFailsOpen(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("from backend"))
	}))
	defer backend.Close()

	// A loopback port with nothing listening: dials fail immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	db := openTestDB(t)
	if err := db.AddService("shop", "shop.com", "", backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListServices()
	if err := db.SetServiceCache(list[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: deadAddr}); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Cached("shop") {
		t.Fatal("shop should be cache-routed")
	}
	rp, _ := reg.Proxy("shop")

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://shop.com/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "from backend" {
		t.Fatalf("GET with varnish down: %d %q, want 200 from backend", rec.Code, rec.Body.String())
	}
	if healthy, _ := reg.IsHealthy("shop"); !healthy {
		t.Error("service marked unhealthy for a Varnish outage")
	}

	rec = httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://shop.com/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("POST with varnish down: %d, want 200 (non-GET/HEAD bypass Varnish entirely)", rec.Code)
	}
}

func TestParseVarnishStats(t *testing.T) {
	want := VarnishStats{Uptime: 60, Hits: 30, Misses: 10, Objects: 7, Evicted: 2, BytesUsed: 1 << 20, BytesFree: 3 << 20}
	v7 := `{"version":1,"timestamp":"2026-09-25T10:53:09","counters":{
		"MAIN.uptime":{"value":60},"MAIN.cache_hit":{"value":30},"MAIN.cache_miss":{"value":10},
		"MAIN.n_object":{"value":7},"MAIN.n_lru_nuked":{"value":2},
		"SMA.s0.g_bytes":{"value":1048576},"SMA.s0.g_space":{"value":3145728},
		"SMA.Transient.g_bytes":{"value":999},"SMA.Transient.g_space":{"value":0}}}`
	v6 := `{"timestamp":"2026-09-25T10:53:09",
		"MAIN.uptime":{"value":60},"MAIN.cache_hit":{"value":30},"MAIN.cache_miss":{"value":10},
		"MAIN.n_object":{"value":7},"MAIN.n_lru_nuked":{"value":2},
		"SMA.s0.g_bytes":{"value":1048576},"SMA.s0.g_space":{"value":3145728},
		"SMA.Transient.g_bytes":{"value":999}}`
	for name, in := range map[string]string{"v7": v7, "v6": v6} {
		got, err := parseVarnishStats([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
}
