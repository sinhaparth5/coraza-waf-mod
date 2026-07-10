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

	"coraza-waf-mod/internal/notify/metrics"
	"coraza-waf-mod/internal/security/adaptive"
	"coraza-waf-mod/internal/security/asn"
	"coraza-waf-mod/internal/security/blocklist"
	"coraza-waf-mod/internal/security/bot"
	"coraza-waf-mod/internal/security/challenge"
	"coraza-waf-mod/internal/security/geo"
	ja3pkg "coraza-waf-mod/internal/security/ja3"
	ja4pkg "coraza-waf-mod/internal/security/ja4"
	"coraza-waf-mod/internal/security/ratelimit"
	"coraza-waf-mod/internal/security/threatscore"
	"coraza-waf-mod/internal/security/waf"
	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"

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
	// scorer and adaptive are fixed for the Handler's lifetime — no mutex
	// needed at this level, since both already lock internally (same
	// reasoning as why ipbl/geoBl/registry aren't wrapped again here).
	scorer         *threatscore.Scorer
	adaptive       *adaptive.Policy
	trustedProxies []*net.IPNet
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

// ServeFingerprintJS serves the vendored FingerprintJS bundle used by the
// challenge page. Registered as GET /_cz/fp.js alongside the other challenge
// routes so it exists regardless of whether bot protection is currently on.
func (h *Handler) ServeFingerprintJS(w http.ResponseWriter, r *http.Request) {
	h.challengerMu.RLock()
	ch := h.challenger
	h.challengerMu.RUnlock()
	if ch == nil {
		http.NotFound(w, r)
		return
	}
	ch.ServeFingerprintJS(w, r)
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

// StopRateLimit stops whichever rate-limit backend is currently active. Call
// this once during process shutdown instead of holding onto the backend
// passed to NewHandler — ReloadRateLimit may have swapped it out any number
// of times since startup, and stopping a stale reference would both panic on
// a backend already stopped by a reload and leak the actually-active one.
func (h *Handler) StopRateLimit() {
	h.ratelimitMu.RLock()
	rl := h.ratelimit
	h.ratelimitMu.RUnlock()
	if rl != nil {
		rl.Stop()
	}
}

// NewHandler builds the proxy pipeline. Pass nil for ch to disable bot
// protection / JS challenge (the default when bot_protection.enabled = false).
func NewHandler(registry *services.Registry, engine *waf.Engine, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, rl ratelimit.Backend, asnLookup *asn.Lookup, ch *challenge.Challenger, scorer *threatscore.Scorer, adaptivePolicy *adaptive.Policy, trustedProxyCIDRs ...string) *Handler {
	return &Handler{
		waf:            engine,
		db:             db,
		ipbl:           ipbl,
		geoBl:          geoBl,
		asnLookup:      asnLookup,
		ratelimit:      rl,
		registry:       registry,
		challenger:     ch,
		scorer:         scorer,
		adaptive:       adaptivePolicy,
		trustedProxies: parseTrustedProxyCIDRs(trustedProxyCIDRs),
	}
}

func (h *Handler) Handle(c echo.Context) error {
	start := time.Now()
	r := c.Request()
	w := c.Response().Writer
	w.Header().Set("Server", serverHeader)

	reqID := generateRequestID()
	w.Header().Set("X-Request-ID", reqID)
	w.Header().Set("X-WAF-Request-ID", reqID)

	clientIP := h.realIP(r)
	app := h.registry.Match(r.Host, r.URL.Path)
	appName := ""
	if app != nil {
		appName = app.Name
	}

	// Enrich once per request — all lookups are in-process memory reads,
	// cached per-connection (see asn.LookupForConn) so a keep-alive
	// connection only pays for the mmdb lookup once.
	asnNum, org := h.asnLookup.LookupForConn(r.RemoteAddr, clientIP)
	tlsVer, tlsCipher, tlsSNI := tlsInfo(r)

	// Bot signal analysis + TLS fingerprints (both O(1), no I/O).
	botAnalysis := bot.Analyze(r)
	// JA4 (primary) and JA3 (legacy): prefer the Cloudflare headers (only set
	// when RemoteAddr is a CF IP), then fall back to the per-connection store
	// populated at TLS handshake time.
	ja3Hash := r.Header.Get("Cf-Ja3-Fp")
	if ja3Hash == "" {
		ja3Hash = ja3pkg.Get(r.RemoteAddr)
	}
	ja4Fp := r.Header.Get("Cf-Ja4")
	if ja4Fp == "" {
		ja4Fp = ja4pkg.Get(r.RemoteAddr)
	}

	// challengerMu guards live hot-reloads from the Settings page. Fetched
	// before meta so the FingerprintJS visitor ID (bound into the bypass
	// cookie at challenge-solve time) can be logged on every request.
	h.challengerMu.RLock()
	ch := h.challenger
	h.challengerMu.RUnlock()
	visitorID := ""
	if ch != nil {
		visitorID = ch.VisitorID(r)
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
		JA4:        ja4Fp,
		VisitorID:  visitorID,
		BotScore:   botAnalysis.Score,
	}

	// Threat-score-driven adaptive enforcement (issue #16): a pure in-memory
	// read of the client's last-computed composite score (issue #12) plus a
	// pure policy decision from it — no I/O, safe on every request. Reflects
	// that IP's *previous* requests, not this one in flight (threatscore.Scorer
	// updates its cache asynchronously on the log-worker goroutine).
	threatScore := h.scorer.CurrentScore(clientIP)
	adaptiveDecision := h.adaptive.Decide(threatScore)

	// The /_cz/ namespace belongs to the challenge system. Its real routes
	// (GET /_cz/challenge etc.) are registered before the catch-all, so any
	// /_cz/ request landing here is an unregistered method/path combo — e.g.
	// a scanner sending HEAD /_cz/challenge. Redirecting it to the challenge
	// would bounce it straight back to itself in an endless 307 loop, and
	// proxying would leak internal paths to the backend, so 404 outright.
	if strings.HasPrefix(r.URL.Path, "/_cz/") {
		h.logRequest(r, appName, clientIP, "", http.StatusNotFound, &waf.Result{}, time.Since(start), meta)
		return c.NoContent(http.StatusNotFound)
	}

	// Bot protection: challenge clients based on global setting + per-service
	// override + threat-score-driven adaptive enforcement (issue #16).
	if ch != nil && !botAnalysis.IsTrustedCrawler {
		svcMode := "inherit"
		if app != nil && app.BotMode != "" {
			svcMode = app.BotMode
		}
		if svcMode != "off" && !ch.PassedChallenge(r) {
			byService := svcMode == "always"
			byBotScore := botAnalysis.Score >= ch.Threshold()
			if byService || byBotScore || adaptiveDecision.ForceChallenge {
				metrics.BotChallengedTotal.WithLabelValues(appName).Inc()
				reason := "bot_challenge"
				if !byService && !byBotScore {
					// The only reason this fired is the adaptive policy —
					// tag it distinctly so it's visible in the logs, same
					// Action-string convention as every other decision here.
					reason = "bot_challenge:adaptive"
				}
				h.logChallenged(r, appName, clientIP, http.StatusTemporaryRedirect, reason, time.Since(start), meta)
				return c.Redirect(http.StatusTemporaryRedirect, ch.ChallengeURL(r.RequestURI))
			}
		}
	}

	// Country lookup (used for logging even when not geo-blocked).
	_, _, country := h.geoBl.Check(r.RemoteAddr, clientIP, appName)

	// 1. IP blocklist — fastest check, no inspection needed.
	blockedByIP, ipReason := h.ipbl.Check(clientIP, appName)
	if blockedByIP {
		metrics.IPBlockedTotal.WithLabelValues(appName).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusForbidden, 0, ipReason, time.Since(start), meta)
		w.Header().Set("X-WAF-Block-Reason", "ip_blocked")
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	// 1.5 Rate limit — cheap per-IP throttle, before geo/WAF inspection.
	// Scaled by threat-score-driven adaptive enforcement (issue #16) when
	// enabled; adaptiveDecision.RateScale is 1.0 (no-op) otherwise.
	h.ratelimitMu.RLock()
	rlBackend := h.ratelimit
	h.ratelimitMu.RUnlock()
	var rlRes ratelimit.Result
	if rlBackend != nil {
		rlRes = rlBackend.AllowScaled(clientIP, adaptiveDecision.RateScale)
	} else {
		rlRes = ratelimit.Result{Allowed: true}
	}
	setRateLimitHeaders(c.Response().Header(), rlRes)
	if !rlRes.Allowed {
		metrics.RateLimitedTotal.WithLabelValues(appName).Inc()
		rlReason := "rate_limited"
		if adaptiveDecision.RateScale != 1.0 {
			rlReason = "rate_limited:adaptive"
		}
		h.logBlocked(r, appName, clientIP, country, http.StatusTooManyRequests, 0, rlReason, time.Since(start), meta)
		secs := int(rlRes.RetryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		c.Response().Header().Set("Retry-After", strconv.Itoa(secs))
		w.Header().Set("X-WAF-Block-Reason", "rate_limited")
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
			w.Header().Set("X-WAF-Block-Reason", "rate_limited")
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		}
	}

	// 2. Geo blocklist — country-level block.
	blockedByGeo, geoReason, _ := h.geoBl.Check(r.RemoteAddr, clientIP, appName)
	if blockedByGeo {
		metrics.GeoBlockedTotal.WithLabelValues(appName, country).Inc()
		h.logBlocked(r, appName, clientIP, country, http.StatusForbidden, 0, geoReason, time.Since(start), meta)
		w.Header().Set("X-WAF-Block-Reason", "geo_blocked")
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
		w.Header().Set("X-WAF-Block-Reason", "waf_rule")
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
	if app.Prefix != "" && services.PrefixMatch(r.URL.Path, app.Prefix) {
		r.URL.Path = services.StripPrefix(r.URL.Path, app.Prefix)
		r.URL.RawPath = ""
	}

	w.Header().Set("X-WAF-Status", "inspected")
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
	JA4        string
	VisitorID  string
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
		JA4:         m.JA4,
		VisitorID:   m.VisitorID,
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
		JA4:         m.JA4,
		VisitorID:   m.VisitorID,
		BotScore:    m.BotScore,
	})
}

// logChallenged logs a bot challenge redirect (307) without marking it as
// Blocked. A challenge is not a definitive deny — the browser solves the JS
// PoW and proceeds normally — so it should not trigger blocked notifications
// or inflate the blocked-request counters. reason is "bot_challenge" for a
// normal challenge or "bot_challenge:adaptive" when issue #16's adaptive
// enforcement forced it; BotStats.ChallengedToday and friends match both via
// `action LIKE 'bot_challenge%'`.
func (h *Handler) logChallenged(r *http.Request, appName, clientIP string, status int, reason string, dur time.Duration, m reqMeta) {
	h.writeLog(storage.RequestLog{
		Timestamp:   time.Now().UTC(),
		AppName:     appName,
		RealIP:      clientIP,
		ProxyIP:     proxyIP(r),
		Method:      r.Method,
		Host:        r.Host,
		Path:        r.URL.Path,
		Query:       m.Query,
		Status:      status,
		Blocked:     false,
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
		JA4:         m.JA4,
		VisitorID:   m.VisitorID,
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

func parseTrustedProxyCIDRs(cidrs []string) []*net.IPNet {
	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("trusted proxy: ignoring invalid CIDR %q: %v", cidr, err)
			continue
		}
		trusted = append(trusted, network)
	}
	return trusted
}

func (h *Handler) realIP(r *http.Request) string {
	remoteIP := socketPeerIP(r.RemoteAddr)

	// Only trust CF-Connecting-IP when the connection actually came from Cloudflare.
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" && isCloudflareIP(remoteIP) {
		return normalizeIP(strings.TrimSpace(ip))
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && h.isTrustedProxy(remoteIP) {
		if idx := strings.Index(xff, ","); idx != -1 {
			return normalizeIP(strings.TrimSpace(xff[:idx]))
		}
		return normalizeIP(strings.TrimSpace(xff))
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" && h.isTrustedProxy(remoteIP) {
		return normalizeIP(strings.TrimSpace(ip))
	}
	return normalizeIP(remoteIP)
}

func (h *Handler) isTrustedProxy(remoteIP string) bool {
	parsed := net.ParseIP(remoteIP)
	if parsed == nil {
		return false
	}
	for _, cidr := range h.trustedProxies {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func socketPeerIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return ip
	}
	return remoteAddr
}

// normalizeIP converts IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to
// their plain IPv4 form so blocklist rules for "127.0.0.1" match regardless of
// whether the OS presents the connection as IPv4 or IPv6. Pure IPv6 addresses
// like ::1 are left as-is.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
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
