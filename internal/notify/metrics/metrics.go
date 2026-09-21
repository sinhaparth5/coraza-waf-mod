// Package metrics exposes Prometheus-format counters, a latency histogram,
// and gauges for internal queue/service health. Scraped via
// {admin.path}/metrics, behind the same Basic Auth as the rest of the admin
// UI — Prometheus scrape configs support basic_auth natively, so this needs
// no separate auth model.
package metrics

import (
	"net/http"
	"time"

	"coraza-waf-mod/internal/storage"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_http_requests_total",
		Help: "Total requests handled, labeled by app and final HTTP status code.",
	}, []string{"app", "status"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "coraza_http_request_duration_seconds",
		Help:    "Request handling latency in seconds, including WAF inspection and proxying.",
		Buckets: prometheus.DefBuckets,
	}, []string{"app"})

	IPBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_ip_blocked_total",
		Help: "Requests denied by the IP blocklist, labeled by app.",
	}, []string{"app"})

	GeoBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_geo_blocked_total",
		Help: "Requests denied by country/geo rules, labeled by app and country code.",
	}, []string{"app", "country"})

	WAFBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_waf_blocked_total",
		Help: "Requests denied by the Coraza WAF, labeled by app and the matched rule's action.",
	}, []string{"app", "action"})

	RateLimitedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_rate_limited_total",
		Help: "Requests denied by the per-IP rate limiter, labeled by app.",
	}, []string{"app"})

	BotChallengedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_bot_challenged_total",
		Help: "Requests redirected to the JS PoW challenge because their bot anomaly score exceeded the threshold.",
	}, []string{"app"})

	// StageDuration breaks RequestDuration's total down by which pipeline
	// stage the time was actually spent in — "enrich" (ASN/bot/TLS/threat-
	// score lookups), "blocklist" (IP+geo checks), "challenge" (bot gate),
	// "ratelimit" (global+per-service), "waf" (Coraza inspection), "proxy"
	// (backend round trip). A request that's
	// blocked or redirected early only contributes to the stages it actually
	// reached, which is the point: RequestDuration alone can't tell you
	// whether a slow reply was spent in the WAF or waiting on the backend,
	// this can. Deliberately not labeled by app too — stage x app would
	// multiply cardinality for a breakdown that's meant to answer "which
	// stage is slow", not "which stage is slow for which app".
	StageDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "coraza_stage_duration_seconds",
		Help:    "Time spent per request-pipeline stage, labeled by stage.",
		Buckets: prometheus.DefBuckets,
	}, []string{"stage"})
)

// currentDB/currentRegistry/currentLimiter back the gauges below. Set once
// from main.go after each is constructed; read lazily on every scrape rather
// than polled on a timer, matching the rest of this codebase's preference for
// passive/pull-based observation over background polling loops.
var (
	currentDB       *storage.DB
	currentRegistry interface{ List() []storage.Service }
	currentLimiter  interface{ TrackedIPs() int }
)

// SetDB makes the log-write queue depth visible to /metrics.
func SetDB(db *storage.DB) { currentDB = db }

// SetRegistry makes the configured-service count visible to /metrics.
func SetRegistry(r interface{ List() []storage.Service }) { currentRegistry = r }

// SetLimiter makes the per-IP bucket count visible to /metrics.
func SetLimiter(l interface{ TrackedIPs() int }) { currentLimiter = l }

var _ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
	Name: "coraza_log_queue_depth",
	Help: "Current number of request-log entries buffered waiting to be written to SQLite.",
}, func() float64 {
	if currentDB == nil {
		return 0
	}
	return float64(currentDB.QueueDepth())
})

var _ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
	Name: "coraza_services_total",
	Help: "Number of backend services currently configured.",
}, func() float64 {
	if currentRegistry == nil {
		return 0
	}
	return float64(len(currentRegistry.List()))
})

var _ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
	Name: "coraza_rate_limit_tracked_ips",
	Help: "Number of per-IP token buckets currently held in memory by the rate limiter.",
}, func() float64 {
	if currentLimiter == nil {
		return 0
	}
	return float64(currentLimiter.TrackedIPs())
})

// RecordRequest updates the request-volume counter and latency histogram.
// Called exactly once per request, regardless of outcome.
func RecordRequest(app, status string, seconds float64) {
	RequestsTotal.WithLabelValues(app, status).Inc()
	RequestDuration.WithLabelValues(app).Observe(seconds)
}

// ObserveStage records how long one pipeline stage took. See StageDuration.
func ObserveStage(stage string, d time.Duration) {
	StageDuration.WithLabelValues(stage).Observe(d.Seconds())
}

// Handler serves the Prometheus text exposition format.
func Handler() http.Handler {
	return promhttp.Handler()
}
