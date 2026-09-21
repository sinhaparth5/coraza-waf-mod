package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/notify/metrics"
	"coraza-waf-mod/internal/proxy"
	"coraza-waf-mod/internal/security/blocklist"
	"coraza-waf-mod/internal/security/geo"
	"coraza-waf-mod/internal/security/ratelimit"
	"coraza-waf-mod/internal/security/waf"
	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// stageSampleCount reads metrics.StageDuration's current observation count
// for one stage label, so tests can assert "this many more observations
// landed" without depending on Handle's exact latency numbers.
func stageSampleCount(t *testing.T, stage string) uint64 {
	t.Helper()
	h, ok := metrics.StageDuration.WithLabelValues(stage).(prometheus.Histogram)
	if !ok {
		t.Fatalf("StageDuration observer for %q is not a prometheus.Histogram", stage)
	}
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

var allStages = []string{"enrich", "blocklist", "challenge", "ratelimit", "waf", "proxy"}

func snapshotStages(t *testing.T) map[string]uint64 {
	t.Helper()
	snap := make(map[string]uint64, len(allStages))
	for _, s := range allStages {
		snap[s] = stageSampleCount(t, s)
	}
	return snap
}

// TestStageMetricsRecordedForFullyProxiedRequest checks that a request which
// clears every gate contributes exactly one observation to every pipeline
// stage's histogram — the mark() calls threaded through Handle (handler.go)
// must cover every stage on the happy path with no double-counting.
func TestStageMetricsRecordedForFullyProxiedRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := newTestHandler(t, backend)
	e := echo.New()
	before := snapshotStages(t)

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	req.Header.Set("X-Real-IP", "198.51.100.9")
	rec := httptest.NewRecorder()
	if err := h.Handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	for _, s := range allStages {
		if got := stageSampleCount(t, s); got != before[s]+1 {
			t.Errorf("stage %q sample count = %d, want %d (before=%d)", s, got, before[s]+1, before[s])
		}
	}
}

// TestStageMetricsStopAtBlocklistForBannedIP checks the other half of the
// contract: a request blocked at the IP blocklist gate must contribute to
// "blocklist" but never reach "challenge", "ratelimit", "waf", or "proxy" —
// confirming mark() calls aren't accidentally placed on a shared path that
// would fire regardless of which stage actually blocked the request.
func TestStageMetricsStopAtBlocklistForBannedIP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "bl.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.AddService("svc", "", "/", backend.URL, 0, 0); err != nil {
		t.Fatalf("add service: %v", err)
	}
	if err := db.AddIPRule("", "203.0.113.77", "block"); err != nil {
		t.Fatalf("add ip rule: %v", err)
	}

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		t.Fatalf("ipbl: %v", err)
	}
	geoBl, err := geo.New("", db)
	if err != nil {
		t.Fatalf("geo: %v", err)
	}
	defer geoBl.Close()
	reg, err := services.New(db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	engine, err := waf.New(config.WAFConfig{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("waf init: %v", err)
	}
	rl := ratelimit.New(config.RateLimitConfig{Enabled: false})
	defer rl.Stop()

	h := proxy.NewHandler(reg, engine, nil, db, ipbl, geoBl, rl, nil, nil, nil, nil)
	e := echo.New()
	before := snapshotStages(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.77:12345"
	rec := httptest.NewRecorder()
	if err := h.Handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	if got := stageSampleCount(t, "blocklist"); got != before["blocklist"]+1 {
		t.Errorf(`stage "blocklist" sample count = %d, want %d`, got, before["blocklist"]+1)
	}
	for _, s := range []string{"challenge", "ratelimit", "waf", "proxy"} {
		if got := stageSampleCount(t, s); got != before[s] {
			t.Errorf("stage %q sample count = %d, want unchanged at %d (request never reached this stage)", s, got, before[s])
		}
	}
}
