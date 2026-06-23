package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/config"
	"coraza-waf-mod/geo"
	"coraza-waf-mod/storage"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

//go:embed templates/*
var templateFS embed.FS

var funcs = template.FuncMap{
	"flag":        countryFlag,
	"flagClass":   func(code string) string { return "fi fi-" + strings.ToLower(code) },
	"statusClass": statusClass,
	"fmtTime":     func(t time.Time) string { return t.Format("02 Jan 15:04:05") },
	"fmtTimeFull": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"fmtDur":      func(ms int64) string { return fmt.Sprintf("%dms", ms) },
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"map": func(pairs ...any) (map[string]any, error) {
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("map: odd number of args")
		}
		m := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			k, ok := pairs[i].(string)
			if !ok {
				return nil, fmt.Errorf("map: key must be string")
			}
			m[k] = pairs[i+1]
		}
		return m, nil
	},
}

// Handler holds all UI dependencies.
type Handler struct {
	cfg         *config.Config
	db          *storage.DB
	ipbl        *blocklist.IPBlocklist
	geoBl       *geo.Blocker
	broadcaster *LogBroadcaster
	tmpls       map[string]*template.Template
}

func NewHandler(cfg *config.Config, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, bc *LogBroadcaster) (*Handler, error) {
	h := &Handler{cfg: cfg, db: db, ipbl: ipbl, geoBl: geoBl, broadcaster: bc}
	if err := h.parseTemplates(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) parseTemplates() error {
	pages := []string{"dashboard", "logs", "ip_rules", "geo_rules"}
	h.tmpls = make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		// log_row.html is included everywhere so logs.html can use {{template "log-row"}}
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS,
			"templates/log_row.html",
			"templates/base.html",
			"templates/"+page+".html",
		)
		if err != nil {
			return fmt.Errorf("parse template %s: %w", page, err)
		}
		h.tmpls[page] = t
	}
	// log-row partial used by the SSE stream handler
	t, err := template.New("log-row").Funcs(funcs).ParseFS(templateFS, "templates/log_row.html")
	if err != nil {
		return fmt.Errorf("parse log-row: %w", err)
	}
	h.tmpls["log-row"] = t
	return nil
}

// Register mounts all admin routes on e under cfg.Admin.Path with basic auth.
func (h *Handler) Register(e *echo.Echo) {
	base := h.cfg.Admin.Path
	g := e.Group(base)
	g.Use(middleware.BasicAuth(func(user, pass string, _ echo.Context) (bool, error) {
		return user == h.cfg.Admin.Username && pass == h.cfg.Admin.Password, nil
	}))

	g.GET("", h.Dashboard)
	g.GET("/logs", h.Logs)
	g.GET("/logs/stream", h.LogsStream)
	g.GET("/ip-rules", h.IPRulesPage)
	g.POST("/ip-rules", h.AddIPRule)
	g.DELETE("/ip-rules/:id", h.DeleteIPRule)
	g.GET("/geo-rules", h.GeoRulesPage)
	g.POST("/geo-rules", h.AddGeoRule)
	g.DELETE("/geo-rules/:id", h.DeleteGeoRule)
}

// ── Dashboard ──────────────────────────────────────────────────────────────────

func (h *Handler) Dashboard(c echo.Context) error {
	stats, err := h.db.GetStats()
	if err != nil {
		return err
	}
	recent, err := h.db.ListRequests(false, "", 20, 0)
	if err != nil {
		return err
	}
	return h.render(c, "dashboard", map[string]any{
		"Stats":  stats,
		"Recent": recent,
		"Apps":   h.cfg.Apps,
	})
}

// ── Live Logs ──────────────────────────────────────────────────────────────────

func (h *Handler) Logs(c echo.Context) error {
	recent := h.broadcaster.Recent()
	// Reverse so newest is first in the initial render
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	return h.render(c, "logs", map[string]any{
		"Recent": recent,
		"Apps":   h.cfg.Apps,
	})
}

// LogsStream is an SSE endpoint that pushes pre-rendered HTML log rows.
func (h *Handler) LogsStream(c echo.Context) error {
	w := c.Response().Writer
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ch := h.broadcaster.Subscribe()
	defer h.broadcaster.Unsubscribe(ch)

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return nil
			}
			var buf bytes.Buffer
			if err := h.tmpls["log-row"].ExecuteTemplate(&buf, "log-row", entry); err != nil {
				continue
			}
			// SSE format: each line prefixed with "data:", blank line to end event
			for _, line := range strings.Split(buf.String(), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-c.Request().Context().Done():
			return nil
		}
	}
}

// ── IP Rules ───────────────────────────────────────────────────────────────────

func (h *Handler) IPRulesPage(c echo.Context) error {
	rules, err := h.db.ListIPRules()
	if err != nil {
		return err
	}
	return h.render(c, "ip_rules", map[string]any{
		"Rules": rules,
		"Apps":  h.cfg.Apps,
	})
}

func (h *Handler) AddIPRule(c echo.Context) error {
	appName := c.FormValue("app_name")
	ip := strings.TrimSpace(c.FormValue("ip"))
	ruleType := c.FormValue("rule_type")

	if ip == "" || (ruleType != "block" && ruleType != "allow") {
		return c.String(http.StatusBadRequest, "invalid input")
	}
	if err := h.db.AddIPRule(appName, ip, ruleType); err != nil {
		return err
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return err
	}
	rules, _ := h.db.ListIPRules()
	return h.renderPartial(c, "ip_rules", "ip-rules-rows", rules)
}

func (h *Handler) DeleteIPRule(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveIPRule(id); err != nil {
		return err
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return err
	}
	rules, _ := h.db.ListIPRules()
	return h.renderPartial(c, "ip_rules", "ip-rules-rows", rules)
}

// ── Geo Rules ─────────────────────────────────────────────────────────────────

func (h *Handler) GeoRulesPage(c echo.Context) error {
	rules, err := h.db.ListGeoRules()
	if err != nil {
		return err
	}
	return h.render(c, "geo_rules", map[string]any{
		"Rules": rules,
		"Apps":  h.cfg.Apps,
	})
}

func (h *Handler) AddGeoRule(c echo.Context) error {
	appName := c.FormValue("app_name")
	code := strings.ToUpper(strings.TrimSpace(c.FormValue("country_code")))
	ruleType := c.FormValue("rule_type")

	if len(code) != 2 || (ruleType != "block" && ruleType != "allow") {
		return c.String(http.StatusBadRequest, "invalid input")
	}
	if err := h.db.AddGeoRule(appName, code, ruleType); err != nil {
		return err
	}
	if err := h.geoBl.Reload(h.db); err != nil {
		return err
	}
	rules, _ := h.db.ListGeoRules()
	return h.renderPartial(c, "geo_rules", "geo-rules-rows", rules)
}

func (h *Handler) DeleteGeoRule(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveGeoRule(id); err != nil {
		return err
	}
	if err := h.geoBl.Reload(h.db); err != nil {
		return err
	}
	rules, _ := h.db.ListGeoRules()
	return h.renderPartial(c, "geo_rules", "geo-rules-rows", rules)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) render(c echo.Context, page string, data any) error {
	t, ok := h.tmpls[page]
	if !ok {
		return fmt.Errorf("template %q not found", page)
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return t.ExecuteTemplate(c.Response().Writer, "base", data)
}

// renderPartial executes a named sub-template from a page template (used for HTMX swaps).
func (h *Handler) renderPartial(c echo.Context, page, tmplName string, data any) error {
	t, ok := h.tmpls[page]
	if !ok {
		return fmt.Errorf("template %q not found", page)
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return t.ExecuteTemplate(c.Response().Writer, tmplName, data)
}

// countryFlag converts an ISO 3166-1 alpha-2 code to its emoji flag.
func countryFlag(code string) string {
	if len(code) != 2 {
		return "🌐"
	}
	r1 := rune(0x1F1E6) + rune(code[0]-'A')
	r2 := rune(0x1F1E6) + rune(code[1]-'A')
	return string([]rune{r1, r2})
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "bg-red-100 text-red-800"
	case status >= 400:
		return "bg-yellow-100 text-yellow-800"
	case status >= 300:
		return "bg-blue-100 text-blue-800"
	default:
		return "bg-green-100 text-green-800"
	}
}
