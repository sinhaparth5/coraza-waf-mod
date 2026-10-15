package services

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func twoBackendRegistry(t *testing.T, a, b, healthPath string) *Registry {
	t.Helper()
	db := openTestDB(t)
	if err := db.AddService("app", "app.example.com", "", a, 0, 0); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListServices()
	if err := db.SetServiceBackends(list[0].ID, []string{a, b}, "round_robin", healthPath, 1); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(reg.stopCheck) })
	return reg
}

func serve(t *testing.T, h http.Handler, method string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "http://app.example.com/", nil))
	return rec.Code
}

// TestPoolFailover is issue #110's "done when": with one of two backends
// stopped, idempotent requests never fail, and the dead backend shows down.
func TestPoolFailover(t *testing.T) {
	var hitsA, hitsB atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsA.Add(1) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsB.Add(1) }))

	reg := twoBackendRegistry(t, a.URL, b.URL, "")
	h, _ := reg.Proxy("app")
	for range 10 {
		if code := serve(t, h, http.MethodGet); code != http.StatusOK {
			t.Fatalf("GET with both backends up = %d", code)
		}
	}
	if hitsA.Load() != 5 || hitsB.Load() != 5 {
		t.Errorf("round robin split = %d/%d, want 5/5", hitsA.Load(), hitsB.Load())
	}

	b.Close()
	for i := range 20 {
		if code := serve(t, h, http.MethodGet); code != http.StatusOK {
			t.Fatalf("GET %d with backend b stopped = %d, want 200 via retry/failover", i, code)
		}
	}
	got := reg.BackendHealth("app")
	if len(got) != 2 || !got[0].Healthy || got[1].Healthy || !got[1].Known {
		t.Errorf("BackendHealth = %+v, want a up and b known down", got)
	}
	if healthy, _ := reg.IsHealthy("app"); !healthy {
		t.Error("service with one live backend reported unhealthy")
	}

	// A POST is never replayed: on a fresh registry (no health history) the
	// rotation reaches the dead backend and that request fails.
	reg = twoBackendRegistry(t, a.URL, b.URL, "")
	h, _ = reg.Proxy("app")
	codes := map[int]int{}
	for range 2 {
		codes[serve(t, h, http.MethodPost)]++
	}
	if codes[http.StatusBadGateway] != 1 {
		t.Errorf("POST codes = %v, want exactly one 502 (no retry for non-idempotent methods)", codes)
	}
}

// TestPoolActiveHealthCheck: a backend failing its health path leaves the
// rotation without any client request hitting it, and rejoins once it
// passes again.
func TestPoolActiveHealthCheck(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer a.Close()
	var bHealthy atomic.Bool
	var bTraffic atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if !bHealthy.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		bTraffic.Add(1)
	}))
	defer b.Close()

	reg := twoBackendRegistry(t, a.URL, b.URL, "/healthz")
	waitFor := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if st := reg.BackendHealth("app")[1]; st.Known && st.Healthy == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("backend b healthy never became %v: %+v", want, reg.BackendHealth("app"))
	}

	waitFor(false)
	h, _ := reg.Proxy("app")
	for range 6 {
		serve(t, h, http.MethodGet)
	}
	if n := bTraffic.Load(); n != 0 {
		t.Errorf("backend failing its health check got %d requests", n)
	}

	bHealthy.Store(true)
	waitFor(true)
	for range 6 {
		serve(t, h, http.MethodGet)
	}
	if bTraffic.Load() == 0 {
		t.Error("backend passing its health check again got no traffic")
	}
}

func TestPoolLeastConn(t *testing.T) {
	p := &pool{leastConn: true}
	for range 3 {
		p.ups = append(p.ups, &upstream{health: &backendHealth{}})
	}
	p.ups[0].inflight.Store(4)
	p.ups[1].inflight.Store(1)
	p.ups[2].inflight.Store(7)
	for range 5 {
		if got := p.pick(nil); got != p.ups[1] {
			t.Fatal("least_conn did not pick the backend with the fewest in-flight requests")
		}
	}
	// Out-of-rotation backends are skipped even when least loaded.
	p.ups[1].health.markDown(time.Now().Add(time.Hour).UnixNano())
	if got := p.pick(nil); got != p.ups[0] {
		t.Error("least_conn picked a backend that is out of rotation")
	}
	// All out of rotation: fall back to all rather than fail.
	for _, u := range p.ups {
		u.health.markDown(time.Now().Add(time.Hour).UnixNano())
	}
	if p.pick(nil) == nil {
		t.Error("pick returned nil with every backend down; want a fallback guess")
	}
}

func TestServiceBackendsRoundTrip(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddService("app", "", "/", "http://a:1", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListServices()
	if err := db.SetServiceBackends(list[0].ID, []string{"http://b:2", "http://c:3"}, "least_conn", "/up", 5); err != nil {
		t.Fatal(err)
	}
	s, _ := db.GetService(list[0].ID)
	if got := s.Backends(); len(got) != 2 || got[0] != "http://b:2" || got[1] != "http://c:3" ||
		s.LBPolicy != "least_conn" || s.HealthPath != "/up" || s.HealthInterval != 5 {
		t.Errorf("service = %+v", s)
	}
}
