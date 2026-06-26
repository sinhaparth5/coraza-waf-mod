package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/asn"
	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/bot"
	"coraza-waf-mod/challenge"
	"coraza-waf-mod/geo"
	ja3pkg "coraza-waf-mod/ja3"
	"coraza-waf-mod/metrics"
	"coraza-waf-mod/ratelimit"
	"coraza-waf-mod/services"
	"coraza-waf-mod/storage"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
)

const serverHeader = "Coraza WAF Mod"

type Handler struct {
	wafMu        sync.RWMutex
	waf          *waf.Engine
	challengerMu sync.RWMutex
	challenger   *challenge.Challenger // nil = bot protection disabled
	ratelimitMu  sync.RWMutex
	ratelimit    ratelimit.Backend
	db           *storage.DB
	ipbl         *blocklist.IPBlocklist
	geoBl        *geo.Blocker
	asnLookup    *asn.Lookup
	registry     *services.Registry
}

// ReloadWAF swaps in a freshly built WAF engine without dropping in-flight
// requests. Called from the SIGHUP handler in main.go.
func (h *Handler) ReloadWAF(e *waf.Engine) {
	h.wafMu.Lock()
	h.waf = e
	h.wafMu.Unlock()
	log.Printf("WAF engine reloaded")
}

// ReloadBotProtection swaps the JS challenge configuration at runtime without
// a restart. Pass nil to disable bot protection. Called from the Settings page.
func (h *Handler) ReloadBotProtection(ch *challenge.Challenger) {
	h.challengerMu.Lock()
	h.challenger = ch
	h.challengerMu.Unlock()
	if ch != nil {
		log.Printf("bot protection reloaded (threshold=%d)", ch.Threshold())
	} else {
		log.Printf("bot protection disabled")
	}
}

// ServeChallengePage proxies to the active challenger's page handler, if any.
// Registered as GET /_cz/challenge so the route always exists even when bot
// protection is toggled on/off at runtime.
func (h *Handler) ServeChallengePage(w http.ResponseWriter, r *http.Request) {
	h.challengerMu.RLock()
	ch := h.challenger
	h.challengerMu.RUnlock()
	if ch == nil {
		http.NotFound(w, r)
		return
	}
	ch.ServePage(w, r)
}

// ServeChallengeVerify proxies to the active challenger's verify handler.
func (h *Handler) ServeChallengeVerify(w http.ResponseWriter, r *http.Request) {
	h.challengerMu.RLock()
	ch := h.challenger
	h.challengerMu.RUnlock()
	if ch == nil {
		http.NotFound(w, r)
		return
	}
	ch.ServeVerify(w, r)
}

// ReloadRateLimit swaps in a new rate-limit backend without dropping in-flight
// requests. The old backend is stopped after the swap. Pass nil to disable
// rate limiting (the Allow call becomes a no-op for nil Backend).
func (h *Handler) ReloadRateLimit(backend ratelimit.Backend) {
	h.ratelimitMu.Lock()
	old := h.ratelimit
	h.ratelimit = backend
	h.ratelimitMu.Unlock()
	if old != nil {
		old.Stop()
	}
	log.Printf("rate limit backend reloaded")
}

// NewHandler builds the proxy pipeline. Pass nil for ch to disable bot
// protection / JS challenge (the default when bot_protection.enabled = false).
func NewHandler(registry *services.Registry, engine *waf.Engine, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, rl ratelimit.Backend, asnLookup *asn.Lookup, ch *challenge.Challenger) *Handler {
	return &Handler{
		waf:        engine,
		db:         db,
		ipbl:       ipbl,
		geoBl:      geoBl,
		asnLookup:  asnLookup,
		ratelimit:  rl,
		registry:   registry,
		challenger: ch,
	}
}

func (h *Handler) Handle(c echo.Context) error {
	start := time.Now()
	r := c.Request()
	w := c.Response().Writer
	w.Header().Set("Server", serverHeader)

	reqID := generateRequestID()
	w.Header().Set("X-Request-ID", reqID)

	clientIP := realIP(r)
	app := h.registry.Match(r.Host, r.URL.Path)
	appName := ""
	if app != nil {
		appName = app.Name
	}

	// Enrich once per request — all lookups are in-process memory reads.
	asnNum, org := h.asnLookup.Lookup(clientIP)
	tlsVer, tlsCipher, tlsSNI := tlsInfo(r)

	// Bot signal analysis + JA3 fingerprint (both O(1), no I/O).
	botAnalysis := bot.Analyze(r)
	// JA3: prefer the Cloudflare header (only set when RemoteAddr is a CF IP),
	// then fall back to the per-connection store populated by TLS handshake.
	ja3Hash := r.Header.Get("Cf-Ja3-Fp")
	if ja3Hash == "" {
		ja3Hash = ja3pkg.Get(r.RemoteAddr)
	}

	meta := reqMeta{
		RequestID:  reqID,
		Proto:      r.Proto,
		TLSVersion: tlsVer,
		TLSCipher:  tlsCipher,
		TLSSNI:     tlsSNI,
		ASN:        asnNum,
		Org:        org,
		Query:      r.URL.RawQuery,
		JA3Hash:    ja3Hash,
		BotScore:   botAnalysis.Score,
	}

	// Bot protection: challenge clients based on global setting + per-service override.
	// challengerMu guards live hot-reloads from the Settings page.
	h.challengerMu.RLock()
	ch := h.challenger
	h.challengerMu.RUnlock()

	if ch != nil && !botAnalysis.IsTrustedCrawler {
		svcMode := "inherit"
		if app != nil && app.BotMode != "" {
			svcMode = app.BotMode
		}
		if svcMode != "off" && !ch.PassedChallenge(r) {
			score := botAnalysis.Score
			if svcMode == "always" || score >= ch.Threshold() {
				metrics.BotChallengedTotal.WithLabelValues(appName).Inc()
				h.logBlocked(r, appName, clientIP, "", http.StatusTemporaryRedirect, 0, "bot_challenge", time.Since(start), meta)
				return c.Redirect(http.StatusTemporaryRedirect, ch.ChallengeURL(r.RequestURI))
			}
		}
	}

	// Country lookup (used for logging even when not geo-blocked).
	_, _, country := h.geoBl.Check(clientIP, appName)

	// 1. IP blocklist — fastest check, no inspection needed.
	blockedByIP, ipReason := h.ipbl.Check(clientIP, appName)
	if blockedByIP {
		metrics.IPBlockedTotal.WithLabelValues(appName).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusForbidden, 0, ipReason, time.Since(start), meta)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	// 1.5 Rate limit — cheap per-IP throttle, before geo/WAF inspection.
	h.ratelimitMu.RLock()
	rlBackend := h.ratelimit
	h.ratelimitMu.RUnlock()
	var rlRes ratelimit.Result
	if rlBackend != nil {
		rlRes = rlBackend.Allow(clientIP)
	} else {
		rlRes = ratelimit.Result{Allowed: true}
	}
	setRateLimitHeaders(c.Response().Header(), rlRes)
	if !rlRes.Allowed {
		metrics.RateLimitedTotal.WithLabelValues(appName).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusTooManyRequests, 0, "rate_limited", time.Since(start), meta)
		secs := int(rlRes.RetryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
	}

	// 1.6 Per-service rate limit — only if the matched service has its own limit.
	if app != nil {
		svRes := h.registry.AllowService(app.Name, clientIP)
		setRateLimitHeaders(c.Response().Header(), svRes)
		if !svRes.Allowed {
			metrics.RateLimitedTotal.WithLabelValues(appName).Inc()
			h.logBlocked(r, appName, clientIP, country, http.StatusTooManyRequests, 0, "rate_limited", time.Since(start), meta)
			secs := int(svRes.RetryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		}
	}

	// 2. Geo blocklist — country-level block.
	blockedByGeo, geoReason, _ := h.geoBl.Check(clientIP, appName)
	if blockedByGeo {
		metrics.GeoBlockedTotal.WithLabelValues(appName, country).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusForbidden, 0, geoReason, time.Since(start), meta)
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied", "country": country})
	}

	// 3. WAF — deep inspection of headers + body.
	h.wafMu.RLock()
	engine := h.waf
	h.wafMu.RUnlock()
	result, err := engine.Check(r, clientIP)
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
		h.logBlocked(r, appName, clientIP, country, status, result.RuleID, result.Action, time.Since(start), meta)
		return c.JSON(status, map[string]any{"error": "request blocked", "rule_id": result.RuleID})
	}

	// 4. Proxy to backend.
	if app == nil {
		h.logRequest(r, appName, clientIP, country, http.StatusBadGateway, result, time.Since(start), meta)
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("no backend configured for host %q", r.Host),
		})
	}
	rp, ok := h.registry.Proxy(app.Name)
	if !ok {
		h.logRequest(r, appName, clientIP, country, http.StatusBadGateway, result, time.Since(start), meta)
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
	h.logRequest(r, appName, clientIP, country, rw.status, result, time.Since(start), meta)
	return nil
}

// ── Logging helpers ───────────────────────────────────────────────────────────

// reqMeta holds per-request enrichment fields computed once at the top of
// Handle() and reused by all logging call-sites.
type reqMeta struct {
	RequestID  string
	Proto      string
	TLSVersion string
	TLSCipher  string
	TLSSNI     string
	ASN        uint
	Org        string
	Query      string
	JA3Hash    string
	BotScore   int
}

func (h *Handler) logRequest(r *http.Request, appName, clientIP, country string, status int, wafResult *waf.Result, dur time.Duration, m reqMeta) {
	h.writeLog(storage.RequestLog{
		Timestamp:   time.Now().UTC(),
		AppName:     appName,
		RealIP:      clientIP,
		ProxyIP:     proxyIP(r),
		Country:     country,
		Method:      r.Method,
		Host:        r.Host,
		Path:        r.URL.Path,
		Query:       m.Query,
		Status:      status,
		Blocked:     wafResult.Blocked,
		RuleID:      wafResult.RuleID,
		Action:      wafResult.Action,
		UserAgent:   r.UserAgent(),
		Duration:    dur.Milliseconds(),
		HeadersJSON: captureHeaders(r),
		RequestID:   m.RequestID,
		Proto:       m.Proto,
		TLSVersion:  m.TLSVersion,
		TLSCipher:   m.TLSCipher,
		TLSSNI:      m.TLSSNI,
		ASN:         m.ASN,
		Org:         m.Org,
		JA3Hash:     m.JA3Hash,
		BotScore:    m.BotScore,
	})
}

func (h *Handler) logBlocked(r *http.Request, appName, clientIP, country string, status, ruleID int, reason string, dur time.Duration, m reqMeta) {
	h.writeLog(storage.RequestLog{
		Timestamp:   time.Now().UTC(),
		AppName:     appName,
		RealIP:      clientIP,
		ProxyIP:     proxyIP(r),
		Country:     country,
		Method:      r.Method,
		Host:        r.Host,
		Path:        r.URL.Path,
		Query:       m.Query,
		Status:      status,
		Blocked:     true,
		RuleID:      ruleID,
		Action:      reason,
		UserAgent:   r.UserAgent(),
		Duration:    dur.Milliseconds(),
		HeadersJSON: captureHeaders(r),
		RequestID:   m.RequestID,
		Proto:       m.Proto,
		TLSVersion:  m.TLSVersion,
		TLSCipher:   m.TLSCipher,
		TLSSNI:      m.TLSSNI,
		ASN:         m.ASN,
		Org:         m.Org,
		JA3Hash:     m.JA3Hash,
		BotScore:    m.BotScore,
	})
}

// writeLog must not block on the database — QueueRequest hands the entry to
// a background worker (see storage.DB.runLogWorker) so a slow or contended
// write never holds open the HTTP connection of the request that caused it.
// Broadcasting to the live-log SSE stream happens inside the worker after the
// DB insert so rows get their real row ID before being pushed to the browser.
func (h *Handler) writeLog(entry storage.RequestLog) {
	metrics.RecordRequest(entry.AppName, strconv.Itoa(entry.Status), float64(entry.Duration)/1000)
	if h.db != nil {
		h.db.QueueRequest(entry)
	}
}

// ── Rate limit headers ────────────────────────────────────────────────────────

// setRateLimitHeaders adds CZ-RateLimit-* informational headers to the
// response. Skipped silently when the limiter is disabled (Limit == 0) so
// services without a rate limit don't get misleading zero-value headers.
func setRateLimitHeaders(h http.Header, res ratelimit.Result) {
	if res.Limit <= 0 {
		return
	}
	h.Set("CZ-RateLimit-Limit", strconv.FormatFloat(res.Limit, 'f', -1, 64))
	h.Set("CZ-RateLimit-Burst", strconv.Itoa(res.Burst))
	h.Set("CZ-RateLimit-Remaining", strconv.Itoa(res.Remaining))
}

// ── Request enrichment helpers ────────────────────────────────────────────────

// generateRequestID returns a 16-char random hex string used as a per-request
// correlation ID (X-Request-ID response header + stored in the DB).
func generateRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// tlsInfo extracts the negotiated TLS version, cipher suite name, and SNI
// from the request's TLS state. All three are empty strings for plain HTTP
// or when TLS is terminated upstream (e.g., Cloudflare).
func tlsInfo(r *http.Request) (version, cipher, sni string) {
	if r.TLS == nil {
		return "", "", ""
	}
	switch r.TLS.Version {
	case tls.VersionTLS13:
		version = "TLS 1.3"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS11:
		version = "TLS 1.1"
	case tls.VersionTLS10:
		version = "TLS 1.0"
	default:
		version = fmt.Sprintf("0x%04x", r.TLS.Version)
	}
	cipher = tls.CipherSuiteName(r.TLS.CipherSuite)
	sni = r.TLS.ServerName
	return
}

// ── IP / header helpers ───────────────────────────────────────────────────────

// proxyIP returns the raw TCP peer address (host only, no port).
// When the WAF sits behind Cloudflare this is a CF edge node IP, not the
// real client — real client IP is resolved separately by realIP().
func proxyIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// hop-by-hop headers that must not be forwarded and carry no diagnostic value.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// captureHeaders serialises all non-hop-by-hop request headers to a compact
// JSON object. Multiple values for the same header are joined with ", ".
func captureHeaders(r *http.Request) string {
	m := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if hopByHop[k] {
			continue
		}
		m[k] = strings.Join(v, ", ")
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ── Real IP ───────────────────────────────────────────────────────────────────

// Cloudflare's published IP ranges (https://www.cloudflare.com/ips/).
// CF-Connecting-IP is only trusted when RemoteAddr falls within these ranges;
// requests that reach the origin directly cannot spoof the header.
var cfCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		// IPv4 — https://www.cloudflare.com/ips-v4
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		// IPv6 — https://www.cloudflare.com/ips-v6
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			cfCIDRs = append(cfCIDRs, network)
		}
	}
}

func isCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range cfCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func realIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Only trust CF-Connecting-IP when the connection actually came from Cloudflare.
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" && isCloudflareIP(remoteIP) {
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
	return remoteIP
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
