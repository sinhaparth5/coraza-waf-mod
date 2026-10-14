package metrics

import (
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

type fakeRegistry struct{}

func (fakeRegistry) List() []storage.Service { return make([]storage.Service, 3) }

type fakeLimiter struct{}

func (fakeLimiter) TrackedIPs() int { return 7 }

func scrape(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}

func TestMetricsExposition(t *testing.T) {
	// Unset sources report zero rather than panicking.
	out := scrape(t)
	for _, want := range []string{"palisade_log_queue_depth 0", "palisade_services_total 0", "palisade_rate_limit_tracked_ips 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}

	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	SetDB(db)
	SetRegistry(fakeRegistry{})
	SetLimiter(fakeLimiter{})
	t.Cleanup(func() { SetDB(nil); SetRegistry(nil); SetLimiter(nil) })

	RecordRequest("shop", "200", 0.01)
	ObserveStage("waf", 5*time.Millisecond)

	out = scrape(t)
	for _, want := range []string{
		`palisade_http_requests_total{app="shop",status="200"} 1`,
		`palisade_http_request_duration_seconds_count{app="shop"} 1`,
		`palisade_stage_duration_seconds_count{stage="waf"} 1`,
		"palisade_services_total 3",
		"palisade_rate_limit_tracked_ips 7",
		"palisade_log_queue_depth 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
