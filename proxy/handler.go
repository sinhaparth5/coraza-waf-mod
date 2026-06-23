package proxy

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/config"
	"coraza-waf-mod/geo"
	"coraza-waf-mod/storage"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	cfg     *config.Config
	waf     *waf.Engine
	db      *storage.DB
	ipbl    *blocklist.IPBlocklist
	geoBl   *geo.Blocker
	proxies map[string]*httputil.ReverseProxy
}

func NewHandler(cfg *config.Config, engine *waf.Engine, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker) *Handler {
	h := &Handler{
		cfg:     cfg,
		waf:     engine,
		db:      db,
		ipbl:    ipbl,
		geoBl:   geoBl,
		proxies: make(map[string]*httputil.ReverseProxy),
	}
	for _, app := range cfg.Apps {
		target, err := url.Parse(app.Backend)
		if err != nil {
			log.Printf("invalid backend URL for app %q: %v", app.Name, err)
			continue
		}
		rp := httputil.NewSingleHostReverseProxy(target)
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error [%s]: %v", app.Name, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
		h.proxies[app.Name] = rp
	}
	return h
}

func (h *Handler) Handle(c echo.Context) error {
	start := time.Now()
	r := c.Request()
	w := c.Response().Writer

	clientIP := realIP(r)
	app := h.matchApp(r)
	appName := ""
	if app != nil {
		appName = app.Name
	}

	// 1. IP blocklist — fastest check, no inspection needed.
	if blocked, reason := h.ipbl.Check(clientIP, appName); blocked {
		log.Printf("IP blocked %s [%s]", clientIP, reason)
		h.logBlocked(r, appName, clientIP, http.StatusForbidden, 0, reason, time.Since(start))
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
	}

	// 2. Geo blocklist — country-level block.
	if blocked, reason, country := h.geoBl.Check(clientIP, appName); blocked {
		log.Printf("Geo blocked %s (%s) [%s]", clientIP, country, reason)
		h.logBlocked(r, appName, clientIP, http.StatusForbidden, 0, reason, time.Since(start))
		return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied", "country": country})
	}

	// 3. WAF — deep inspection of headers + body.
	result, err := h.waf.Check(r, clientIP)
	if err != nil {
		log.Printf("waf error: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
	if result.Blocked {
		status := result.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		log.Printf("WAF blocked %s %s (rule %d, action %s)", clientIP, r.RequestURI, result.RuleID, result.Action)
		h.logBlocked(r, appName, clientIP, status, result.RuleID, result.Action, time.Since(start))
		return c.JSON(status, map[string]any{"error": "request blocked", "rule_id": result.RuleID})
	}

	// 4. Proxy to backend.
	if app == nil {
		h.logRequest(r, appName, clientIP, http.StatusBadGateway, result, time.Since(start))
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("no backend configured for host %q", r.Host),
		})
	}
	rp, ok := h.proxies[app.Name]
	if !ok {
		h.logRequest(r, appName, clientIP, http.StatusBadGateway, result, time.Since(start))
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "proxy not initialised"})
	}

	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	rp.ServeHTTP(rw, r)
	h.logRequest(r, appName, clientIP, rw.status, result, time.Since(start))
	return nil
}

// ── Logging helpers ───────────────────────────────────────────────────────────

func (h *Handler) logRequest(r *http.Request, appName, clientIP string, status int, wafResult *waf.Result, dur time.Duration) {
	h.writeLog(storage.RequestLog{
		Timestamp: time.Now().UTC(),
		AppName:   appName,
		RealIP:    clientIP,
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

func (h *Handler) logBlocked(r *http.Request, appName, clientIP string, status, ruleID int, reason string, dur time.Duration) {
	h.writeLog(storage.RequestLog{
		Timestamp: time.Now().UTC(),
		AppName:   appName,
		RealIP:    clientIP,
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

func (h *Handler) writeLog(entry storage.RequestLog) {
	if h.db == nil {
		return
	}
	if err := h.db.InsertRequest(entry); err != nil {
		log.Printf("db log error: %v", err)
	}
}

// ── App routing ───────────────────────────────────────────────────────────────

// matchApp returns the first app whose Host or Prefix matches the request.
// Falls back to the first app if nothing matches.
func (h *Handler) matchApp(r *http.Request) *config.App {
	host := strings.ToLower(strings.Split(r.Host, ":")[0])

	for i, app := range h.cfg.Apps {
		if app.Host != "" && strings.ToLower(app.Host) == host {
			return &h.cfg.Apps[i]
		}
		if app.Prefix != "" && strings.HasPrefix(r.URL.Path, app.Prefix) {
			return &h.cfg.Apps[i]
		}
	}
	if len(h.cfg.Apps) > 0 {
		return &h.cfg.Apps[0]
	}
	return nil
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
