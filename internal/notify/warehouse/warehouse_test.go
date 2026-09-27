package warehouse

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

// recorder stands in for ClickHouse: it records every query + body it was
// POSTed, which is the whole contract this package has with the outside.
type recorder struct {
	mu      sync.Mutex
	queries []string
	bodies  map[string]string // query -> body, last write wins
	srv     *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{bodies: map[string]string{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		q := req.URL.Query().Get("query")
		r.mu.Lock()
		r.queries = append(r.queries, q)
		if len(body) > 0 {
			r.bodies[q] = string(body)
		}
		r.mu.Unlock()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) sawQuery(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, q := range r.queries {
		if strings.Contains(q, substr) {
			return true
		}
	}
	return false
}

func (r *recorder) body(query string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bodies[query]
}

// fakeStore returns one row per dimension so the snapshot has something to
// ship without needing a real database.
type fakeStore struct{}

func (fakeStore) ListIPRules() ([]storage.IPRule, error) {
	return []storage.IPRule{{ID: 1, IP: "203.0.113.5", RuleType: "block", Note: "Auto-banned — scan"}}, nil
}
func (fakeStore) ListGeoRules() ([]storage.GeoRule, error) {
	return []storage.GeoRule{{ID: 1, CountryCode: "CN", RuleType: "block"}}, nil
}
func (fakeStore) ListServices() ([]storage.Service, error) {
	return []storage.Service{{ID: 1, Name: "api", Backend: "http://127.0.0.1:9000"}}, nil
}
func (fakeStore) ListIPThreatScores() ([]storage.IPThreatScore, error) {
	return []storage.IPThreatScore{{IP: "203.0.113.5", Total: 70, AutobanScore: 40, BotScore: 15}}, nil
}
func (fakeStore) ListJA4Reputation() ([]storage.JA4Reputation, error) {
	return []storage.JA4Reputation{{JA4: "t13d1516h2_8daaf6152771_02713d6af862", Hits: 9, BlockedHits: 7}}, nil
}

// TestNewCreatesSchema is the "first run provisions itself" guarantee: an
// empty ClickHouse must come up fully usable with no manual DDL step.
func TestNewCreatesSchema(t *testing.T) {
	r := newRecorder(t)
	s, err := New(r.srv.URL+"/?database=waf", fakeStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Stop()

	if !r.sawQuery("CREATE DATABASE IF NOT EXISTS waf") {
		t.Error("database was never created")
	}
	for _, table := range []string{
		"waf_requests", "waf_ip_rules", "waf_geo_rules",
		"waf_services", "waf_threat_scores", "waf_ja4_reputation",
	} {
		if !r.sawQuery("CREATE TABLE IF NOT EXISTS " + table) {
			t.Errorf("table %s was never created", table)
		}
	}
}

// TestPushSerializesJSONEachRow pins the wire format and the column
// mapping. A wrong key name here is silently dropped by ClickHouse rather
// than rejected, so this is the check that would catch it.
func TestPushSerializesJSONEachRow(t *testing.T) {
	r := newRecorder(t)
	s, err := New(r.srv.URL, fakeStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := time.Date(2026, 9, 27, 10, 30, 0, 0, time.UTC)
	s.Push(storage.RequestLog{
		Timestamp: ts, AppName: "api", RealIP: "203.0.113.5", Country: "CN",
		Method: "POST", Host: "x.test", Path: "/login", Status: 403,
		Blocked: true, RuleID: 942100, Action: "waf_rule", Duration: 12,
		JA4: "t13d", BotScore: 8,
	})
	s.Stop() // drains and flushes

	body := r.body("INSERT INTO waf_requests FORMAT JSONEachRow")
	if body == "" {
		t.Fatal("no rows were inserted")
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d JSON lines, want 1", len(lines))
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("row is not valid JSON: %v", err)
	}
	for key, want := range map[string]any{
		"ts":          "2026-09-27 10:30:00.000",
		"app_name":    "api",
		"real_ip":     "203.0.113.5",
		"status":      float64(403),
		"blocked":     float64(1), // UInt8, not a JSON bool
		"rule_id":     float64(942100),
		"action":      "waf_rule",
		"duration_ms": float64(12),
	} {
		if got := row[key]; got != want {
			t.Errorf("row[%q] = %v, want %v", key, got, want)
		}
	}
	// headers_json can carry Authorization/Cookie values — it must never
	// reach a second system.
	if _, ok := row["headers_json"]; ok {
		t.Error("headers_json must not be shipped to the warehouse")
	}
}

// TestSnapshotShipsEveryDimension guards the "everything the dashboard has,
// not just requests" requirement from issue #94.
func TestSnapshotShipsEveryDimension(t *testing.T) {
	r := newRecorder(t)
	s, err := New(r.srv.URL, fakeStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Stop()

	for _, table := range []string{
		"waf_ip_rules", "waf_geo_rules", "waf_services",
		"waf_threat_scores", "waf_ja4_reputation",
	} {
		q := "INSERT INTO " + table + " FORMAT JSONEachRow"
		if r.body(q) == "" {
			t.Errorf("%s was never snapshotted", table)
		}
	}
	// Spot-check one payload end to end.
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(
		r.body("INSERT INTO waf_threat_scores FORMAT JSONEachRow"))), &row); err != nil {
		t.Fatalf("threat score row: %v", err)
	}
	if row["ip"] != "203.0.113.5" || row["autoban_score"] != float64(40) {
		t.Errorf("threat score breakdown lost: %v", row)
	}
}

func TestNewRejectsBadURL(t *testing.T) {
	r := newRecorder(t)
	host := strings.TrimPrefix(r.srv.URL, "http://")
	tests := []struct {
		name string
		url  string
	}{
		{"unsupported scheme", "tcp://" + host},
		{"database name with SQL", "http://" + host + "/?database=waf;DROP"},
		{"database name with a dash", "http://" + host + "/?database=waf-analytics"},
		{"unparseable", "http://[::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.url, fakeStore{}); err == nil {
				t.Errorf("New(%q) succeeded, want error", tt.url)
			}
		})
	}
}

// TestPushNeverBlocks is the load-bearing property: Push runs on the single
// log-worker goroutine, so a stalled warehouse must drop entries rather
// than back up into the request path.
func TestPushNeverBlocks(t *testing.T) {
	r := newRecorder(t)
	s, err := New(r.srv.URL, fakeStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Stop()

	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize*2; i++ {
			s.Push(storage.RequestLog{Timestamp: time.Now(), AppName: "flood"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Push blocked under a queue-overflowing flood")
	}
}
