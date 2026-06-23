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

	"coraza-waf-mod/config"
	"coraza-waf-mod/storage"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	cfg     *config.Config
	waf     *waf.Engine
	db      *storage.DB
	proxies map[string]*httputil.ReverseProxy
}

func NewHandler(cfg *config.Config, engine *waf.Engine, db *storage.DB) *Handler {
	h := &Handler{
		cfg:     cfg,
		waf:     engine,
		db:      db,
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

	// WAF check.
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
		h.logRequest(r, appName, clientIP, status, result, time.Since(start))
		return c.JSON(status, map[string]any{
			"error":   "request blocked",
			"rule_id": result.RuleID,
		})
	}

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

	// Wrap the ResponseWriter to capture the status code for logging.
	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	rp.ServeHTTP(rw, r)
	h.logRequest(r, appName, clientIP, rw.status, result, time.Since(start))
	return nil
}

func (h *Handler) logRequest(r *http.Request, appName, clientIP string, status int, wafResult *waf.Result, dur time.Duration) {
	if h.db == nil {
		return
	}
	entry := storage.RequestLog{
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
	}
	if err := h.db.InsertRequest(entry); err != nil {
		log.Printf("db log error: %v", err)
	}
}

// matchApp returns the first app whose Host or Prefix matches the request.
// Falls back to the first app in the list if nothing matches.
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

// realIP extracts the true client IP, giving priority to Cloudflare headers.
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

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
