package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/geo"
	"coraza-waf-mod/metrics"
	"coraza-waf-mod/ratelimit"
	"coraza-waf-mod/services"
	"coraza-waf-mod/storage"
	"coraza-waf-mod/ui"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
)

const serverHeader = "Coraza WAF Mod"

type Handler struct {
	waf         *waf.Engine
	db          *storage.DB
	ipbl        *blocklist.IPBlocklist
	geoBl       *geo.Blocker
	ratelimit   *ratelimit.Limiter
	broadcaster *ui.LogBroadcaster
	registry    *services.Registry
}

func NewHandler(registry *services.Registry, engine *waf.Engine, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, rl *ratelimit.Limiter, bc *ui.LogBroadcaster) *Handler {
	return &Handler{
		waf:         engine,
		db:          db,
		ipbl:        ipbl,
		geoBl:       geoBl,
		ratelimit:   rl,
		broadcaster: bc,
		registry:    registry,
	}
}

func (h *Handler) Handle(c echo.Context) error {
	start := time.Now()
	r := c.Request()
	w := c.Response().Writer
	w.Header().Set("Server", serverHeader)

	clientIP := realIP(r)
	app := h.registry.Match(r.Host, r.URL.Path)
	appName := ""
	if app != nil {
		appName = app.Name
	}

	// Country lookup (used for logging even when not geo-blocked).
	_, _, country := h.geoBl.Check(clientIP, appName)

	// 1. IP blocklist — fastest check, no inspection needed.
	blockedByIP, ipReason := h.ipbl.Check(clientIP, appName)
	if blockedByIP {
		metrics.IPBlockedTotal.WithLabelValues(appName).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusForbidden, 0, ipReason, time.Since(start))
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	// 1.5 Rate limit — cheap per-IP throttle, before geo/WAF inspection.
	allowed, retryAfter := h.ratelimit.Allow(clientIP)
	if !allowed {
		metrics.RateLimitedTotal.WithLabelValues(appName).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusTooManyRequests, 0, "rate_limited", time.Since(start))
		secs := int(retryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
	}

	// 2. Geo blocklist — country-level block.
	blockedByGeo, geoReason, _ := h.geoBl.Check(clientIP, appName)
	if blockedByGeo {
		metrics.GeoBlockedTotal.WithLabelValues(appName, country).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusForbidden, 0, geoReason, time.Since(start))
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied", "country": country})
	}

	// 3. WAF — deep inspection of headers + body.
	result, err := h.waf.Check(r, clientIP)
	if err != nil {
		log.Printf("waf error: %v", err)
		metrics.RecordRequest(appName, strconv.Itoa(http.StatusInternalServerError), time.Since(start).Seconds())
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
	if result.Blocked {
		status := result.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		metrics.WAFBlockedTotal.WithLabelValues(appName, result.Action).Inc()
		h.logBlocked(r, appName, clientIP, country, status, result.RuleID, result.Action, time.Since(start))
		return c.JSON(status, map[string]any{"error": "request blocked", "rule_id": result.RuleID})
	}

	// 4. Proxy to backend.
	if app == nil {
		h.logRequest(r, appName, clientIP, country, http.StatusBadGateway, result, time.Since(start))
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("no backend configured for host %q", r.Host),
		})
	}
	rp, ok := h.registry.Proxy(app.Name)
	if !ok {
		h.logRequest(r, appName, clientIP, country, http.StatusBadGateway, result, time.Since(start))
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "proxy not initialised"})
	}

	// Avoid double-sending Server: httputil.ReverseProxy copies the
	// backend's response headers with Header.Add (not Set), so the value we
	// set above would duplicate alongside the one ModifyResponse sets from
	// the backend's response. Clear it here and let ModifyResponse own it.
	w.Header().Del("Server")

	// Prefix-matched services route by path, and the backend is generally
	// written assuming it's mounted at "/" (it has no idea what prefix the
	// proxy used to find it) — so strip the prefix before forwarding, same
	// as nginx's "location /foo/ { proxy_pass http://backend/; }". Host
	// matches are virtual hosting, not path routing, so the path is left
	// untouched for those. Restore the original path before logging so the
	// admin UI shows what the client actually requested.
	originalPath := r.URL.Path
	if app.Prefix != "" && strings.HasPrefix(r.URL.Path, app.Prefix) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, app.Prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		r.URL.RawPath = ""
	}

	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	rp.ServeHTTP(rw, r)
	r.URL.Path = originalPath
	h.logRequest(r, appName, clientIP, country, rw.status, result, time.Since(start))
	return nil
}

// ── Logging helpers ───────────────────────────────────────────────────────────

func (h *Handler) logRequest(r *http.Request, appName, clientIP, country string, status int, wafResult *waf.Result, dur time.Duration) {
	h.writeLog(storage.RequestLog{
		Timestamp: time.Now().UTC(),
		AppName:   appName,
		RealIP:    clientIP,
		Country:   country,
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.Path,
		Status:    status,
		Blocked:   wafResult.Blocked,
		RuleID:    wafResult.RuleID,
		Action:    wafResult.Action,
		UserAgent: r.UserAgent(),
		Duration:  dur.Milliseconds(),
	})
}

func (h *Handler) logBlocked(r *http.Request, appName, clientIP, country string, status, ruleID int, reason string, dur time.Duration) {
	h.writeLog(storage.RequestLog{
		Timestamp: time.Now().UTC(),
		AppName:   appName,
		RealIP:    clientIP,
		Country:   country,
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.Path,
		Status:    status,
		Blocked:   true,
		RuleID:    ruleID,
		Action:    reason,
		UserAgent: r.UserAgent(),
		Duration:  dur.Milliseconds(),
	})
}

// writeLog must not block on the database — QueueRequest hands the entry to
// a background worker (see storage.DB.runLogWorker) so a slow or contended
// write never holds open the HTTP connection of the request that caused it.
func (h *Handler) writeLog(entry storage.RequestLog) {
	metrics.RecordRequest(entry.AppName, strconv.Itoa(entry.Status), float64(entry.Duration)/1000)
	if h.db != nil {
		h.db.QueueRequest(entry)
	}
	if h.broadcaster != nil {
		h.broadcaster.Broadcast(entry)
	}
}

// ── Real IP ───────────────────────────────────────────────────────────────────

func realIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// ── responseWriter ────────────────────────────────────────────────────────────

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Hijack and Flush passthrough are required because wrapping
// http.ResponseWriter in a struct hides any capabilities not part of the
// http.ResponseWriter interface itself (Go doesn't promote them just because
// the underlying concrete value supports them). Without Hijack,
// httputil.ReverseProxy can't upgrade a connection to a WebSocket — which
// breaks any backend that uses one, e.g. a Vite dev server's HMR client.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
