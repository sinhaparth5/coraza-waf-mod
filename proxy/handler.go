package proxy

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"coraza-waf-mod/config"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
)

type Handler struct {
	cfg     *config.Config
	waf     *waf.Engine
	proxies map[string]*httputil.ReverseProxy
}

func NewHandler(cfg *config.Config, engine *waf.Engine) *Handler {
	h := &Handler{
		cfg:     cfg,
		waf:     engine,
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
	r := c.Request()
	w := c.Response().Writer

	clientIP := realIP(r)

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
		return c.JSON(status, map[string]any{
			"error":   "request blocked",
			"rule_id": result.RuleID,
		})
	}

	app := h.matchApp(r)
	if app == nil {
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("no backend configured for host %q", r.Host),
		})
	}

	rp, ok := h.proxies[app.Name]
	if !ok {
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "proxy not initialised"})
	}

	rp.ServeHTTP(w, r)
	return nil
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
		// XFF can be a comma-separated list; take the leftmost (original client).
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
