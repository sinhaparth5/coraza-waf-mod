package proxy_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"palisade/internal/config"
	"palisade/internal/security/challenge"
	"palisade/internal/security/ratelimit"

	"github.com/labstack/echo/v4"
)

// Benchmarks for the whole Handle pipeline (issue #109). Baseline numbers
// and how to compare against them are in BENCHMARKS.md.
//
//	make bench

func benchHandler(b *testing.B) (*echo.Echo, func(*http.Request) int) {
	// Startup log lines land mid-way through benchmark result lines and
	// break benchstat's parsing.
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(os.Stderr) })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	b.Cleanup(backend.Close)

	h := newTestHandler(b, backend)
	// Every stage active: a challenger (browser-like requests score under its
	// threshold, so they pass the gate without a cookie) and a rate limiter
	// too generous to ever trip.
	h.ReloadBotProtection(challenge.New("bench-secret", 3600, 5))
	rl := ratelimit.New(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1e9, Burst: 1e9})
	b.Cleanup(rl.Stop)
	h.ReloadRateLimit(rl)

	e := echo.New()
	return e, func(req *http.Request) int {
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		return rec.Code
	}
}

var benchSeq atomic.Int64

// newBenchRequest builds a browser-like request. unique adds a fresh query
// value so the WAF verdict cache can't answer it, measuring a full rule run.
func newBenchRequest(method, target, body string, unique bool) *http.Request {
	if unique {
		target += "&n=" + strconv.FormatInt(benchSeq.Add(1), 10)
	}
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func BenchmarkHandle(b *testing.B) {
	largeBody := `{"items":[` + strings.Repeat(`{"id":12345,"name":"widget","tags":["a","b","c"]},`, 1200) + `{}]}` // ~64 KiB
	for _, tc := range []struct {
		name   string
		method string
		target string
		body   string
		unique bool
		want   int
	}{
		{"clean", "GET", "/products?page=2", "", true, http.StatusOK},
		{"clean_cached", "GET", "/products?page=2", "", false, http.StatusOK},
		{"waf_blocked", "GET", "/search?q=1'+OR+'1'='1", "", true, http.StatusForbidden},
		{"large_body", "POST", "/api/orders?x=1", largeBody, true, http.StatusOK},
	} {
		b.Run(tc.name, func(b *testing.B) {
			_, do := benchHandler(b)
			if code := do(newBenchRequest(tc.method, tc.target, tc.body, tc.unique)); code != tc.want {
				b.Fatalf("status = %d, want %d", code, tc.want)
			}
			b.SetBytes(int64(len(tc.body)))
			b.ReportAllocs()
			for b.Loop() {
				do(newBenchRequest(tc.method, tc.target, tc.body, tc.unique))
			}
		})
	}
}

// BenchmarkHandleParallel is the throughput number: clean requests from all
// cores at once, which is where shared locks and the DB log queue show up.
func BenchmarkHandleParallel(b *testing.B) {
	_, do := benchHandler(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if code := do(newBenchRequest("GET", "/products?page=2", "", true)); code != http.StatusOK {
				b.Errorf("status = %d", code)
				return
			}
		}
	})
}
