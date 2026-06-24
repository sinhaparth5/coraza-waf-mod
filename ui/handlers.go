package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/config"
	"coraza-waf-mod/geo"
	"coraza-waf-mod/metrics"
	"coraza-waf-mod/services"
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
	"shortDate": func(s string) string {
		if len(s) < 10 {
			return s
		}
		return s[:10]
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
	registry    *services.Registry
	broadcaster *LogBroadcaster
	tmpls       map[string]*template.Template
	staticJS    fs.FS
}

// NewHandler builds the UI handler. jsFS must contain the minified JS
// assets at "static/js/dist/*" (see assets.go in the repo root); it's
// served under /<admin_path>/static/js/.
func NewHandler(cfg *config.Config, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, registry *services.Registry, bc *LogBroadcaster, jsFS embed.FS) (*Handler, error) {
	sub, err := fs.Sub(jsFS, "static/js/dist")
	if err != nil {
		return nil, fmt.Errorf("sub static/js/dist: %w", err)
	}
	h := &Handler{cfg: cfg, db: db, ipbl: ipbl, geoBl: geoBl, registry: registry, broadcaster: bc, staticJS: sub}
	if err := h.parseTemplates(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) parseTemplates() error {
	pages := []string{"dashboard", "logs", "ip_rules", "geo_rules", "services"}
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

	// notifications partial used by the bell dropdown
	notif, err := template.New("notifications-panel").Funcs(funcs).ParseFS(templateFS, "templates/notifications.html")
	if err != nil {
		return fmt.Errorf("parse notifications: %w", err)
	}
	h.tmpls["notifications"] = notif
	return nil
}

// Register mounts all admin routes on e under cfg.Admin.Path with basic auth.
func (h *Handler) Register(e *echo.Echo) {
	base := h.cfg.Admin.Path
	g := e.Group(base)
	g.Use(middleware.BasicAuth(func(user, pass string, _ echo.Context) (bool, error) {
		return user == h.cfg.Admin.Username && pass == h.cfg.Admin.Password, nil
	}))

	g.StaticFS("/static/js", h.staticJS)
	g.GET("/metrics", echo.WrapHandler(metrics.Handler()))

	g.GET("", h.Dashboard)
	g.GET("/api/notifications", h.NotificationsPanel)
	g.GET("/api/notifications/stream", h.NotificationsStream)
	g.POST("/api/notifications/seen", h.MarkNotificationsSeen)
	g.GET("/api/traffic", h.TrafficSeries)
	g.GET("/api/threats", h.ThreatsSeries)
	g.GET("/logs", h.Logs)
	g.GET("/logs/stream", h.LogsStream)
	g.GET("/ip-rules", h.IPRulesPage)
	g.POST("/ip-rules", h.AddIPRule)
	g.DELETE("/ip-rules/:id", h.DeleteIPRule)
	g.GET("/geo-rules", h.GeoRulesPage)
	g.POST("/geo-rules", h.AddGeoRule)
	g.DELETE("/geo-rules/:id", h.DeleteGeoRule)
	g.GET("/services", h.ServicesPage)
	g.GET("/services/rows", h.ServicesRows)
	g.POST("/services", h.AddService)
	g.DELETE("/services/:id", h.DeleteService)
	g.POST("/services/tls/upload", h.UploadServiceTLS)
	g.POST("/services/tls/auto", h.EnableServiceAutoTLS)
	g.POST("/services/tls/clear", h.ClearServiceTLS)
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
	topBlocked, err := h.db.ListRequests(true, "", 5, 0)
	if err != nil {
		return err
	}
	blockRate := 0
	if stats.TotalToday > 0 {
		blockRate = stats.BlockedToday * 100 / stats.TotalToday
	}
	// SVG donut arcs: circumference of r=50 circle ≈ 314
	const circ = 314
	blockedArc := 0
	allowedArc := circ
	if stats.TotalToday > 0 {
		blockedArc = stats.BlockedToday * circ / stats.TotalToday
		allowedArc = circ - blockedArc
	}
	return h.render(c, "dashboard", map[string]any{
		"Stats":      stats,
		"Recent":     recent,
		"TopBlocked": topBlocked,
		"BlockRate":  blockRate,
		"AllowedArc": allowedArc,
		"BlockedArc": blockedArc,
		"Apps":       h.registry.List(),
	})
}

// unreadAlertCount returns how many blocked requests happened since the
// admin last marked notifications as read.
func (h *Handler) unreadAlertCount() int {
	seenAt, err := h.db.NotificationsSeenAt()
	if err != nil {
		return 0
	}
	n, err := h.db.CountBlockedSince(seenAt)
	if err != nil {
		return 0
	}
	return n
}

// NotificationsStream is an SSE endpoint that pushes the updated unread
// notification count whenever a new request is blocked, so the bell badge
// updates live without a page reload.
func (h *Handler) NotificationsStream(c echo.Context) error {
	w := c.Response().Writer
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
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
			if !entry.Blocked {
				continue
			}
			fmt.Fprintf(w, "data: %d\n\n", h.unreadAlertCount())
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-c.Request().Context().Done():
			return nil
		}
	}
}

// NotificationsPanel renders the bell dropdown contents: the most recent
// real blocked requests, newest first.
func (h *Handler) NotificationsPanel(c echo.Context) error {
	rows, err := h.db.ListRequests(true, "", 6, 0)
	if err != nil {
		return err
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["notifications"].ExecuteTemplate(c.Response().Writer, "notifications-panel", map[string]any{
		"Rows":      rows,
		"AdminPath": h.cfg.Admin.Path,
	})
}

// MarkNotificationsSeen clears the unread notification badge.
func (h *Handler) MarkNotificationsSeen(c echo.Context) error {
	if err := h.db.MarkNotificationsSeen(); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// TrafficSeries returns hourly allowed/blocked request counts for the last
// 24h as JSON, for the dashboard traffic chart. Gaps with no traffic are
// filled with zero so the chart stays continuous.
func (h *Handler) TrafficSeries(c echo.Context) error {
	const hours = 24
	points, err := h.db.GetHourlyTraffic(hours)
	if err != nil {
		return err
	}
	byHour := make(map[string]storage.HourlyPoint, len(points))
	for _, p := range points {
		byHour[p.Hour.Format("2006-01-02T15:04:05Z")] = p
	}

	now := time.Now().UTC().Truncate(time.Hour)
	labels := make([]string, 0, hours)
	allowed := make([]int, 0, hours)
	blocked := make([]int, 0, hours)
	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		p := byHour[t.Format("2006-01-02T15:04:05Z")]
		labels = append(labels, t.Format("15:00"))
		allowed = append(allowed, p.Total-p.Blocked)
		blocked = append(blocked, p.Blocked)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"labels":  labels,
		"allowed": allowed,
		"blocked": blocked,
	})
}

// ThreatsSeries returns the top blocked-from countries in the last 24h as
// JSON, for the dashboard "Recent threats" bar chart.
func (h *Handler) ThreatsSeries(c echo.Context) error {
	rows, err := h.db.GetTopBlockedCountries(6, 24)
	if err != nil {
		return err
	}
	labels := make([]string, 0, len(rows))
	counts := make([]int, 0, len(rows))
	for _, r := range rows {
		labels = append(labels, r.Country)
		counts = append(counts, r.Count)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"labels": labels,
		"counts": counts,
	})
}

// ── Live Logs ──────────────────────────────────────────────────────────────────

const logsPageSize = 50

// Logs serves the logs page. The row data always comes from the database
// (so it survives restarts, unlike the in-memory broadcast ring buffer).
// In "live" mode (no filters, page 1) the page also keeps an SSE connection
// open so brand-new requests get prepended in real time. Any filter, or
// paging past page 1, freezes the view into a static "history" page.
func (h *Handler) Logs(c echo.Context) error {
	q := c.QueryParams()

	filter := storage.LogFilter{
		AppName:     q.Get("app"),
		StatusClass: q.Get("status"),
	}
	fromStr := q.Get("from")
	toStr := q.Get("to")
	if fromStr != "" {
		if t, err := time.Parse("2006-01-02T15:04", fromStr); err == nil {
			filter.From = t
		}
	}
	if toStr != "" {
		if t, err := time.Parse("2006-01-02T15:04", toStr); err == nil {
			filter.To = t
		}
	}

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	filter.Limit = logsPageSize
	filter.Offset = (page - 1) * logsPageSize

	hasFilter := filter.AppName != "" || filter.StatusClass != "" || fromStr != "" || toStr != ""
	live := !hasFilter && page == 1 && q.Get("mode") != "history"

	rows, total, err := h.db.ListRequestsFiltered(filter)
	if err != nil {
		return err
	}

	return h.render(c, "logs", map[string]any{
		"Apps":         h.registry.List(),
		"History":      !live,
		"Recent":       rows,
		"Total":        total,
		"CurPage":      page,
		"TotalPages":   max(1, (total+logsPageSize-1)/logsPageSize),
		"FilterApp":    filter.AppName,
		"FilterStatus": filter.StatusClass,
		"FilterFrom":   fromStr,
		"FilterTo":     toStr,
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
		"Apps":  h.registry.List(),
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
		"Apps":  h.registry.List(),
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

// ── Services ──────────────────────────────────────────────────────────────────

// ServiceView pairs a stored service with its last-known reachability, for
// rendering the status dot in the services table.
type ServiceView struct {
	storage.Service
	Healthy bool
	Known   bool
}

func (h *Handler) serviceViews() []ServiceView {
	list := h.registry.List()
	out := make([]ServiceView, len(list))
	for i, s := range list {
		healthy, known := h.registry.IsHealthy(s.Name)
		out[i] = ServiceView{Service: s, Healthy: healthy, Known: known}
	}
	return out
}

func (h *Handler) ServicesPage(c echo.Context) error {
	return h.render(c, "services", map[string]any{
		"Services": h.serviceViews(),
	})
}

// ServicesRows re-renders just the services table body, polled periodically
// by the page so the reachability dot updates live.
func (h *Handler) ServicesRows(c echo.Context) error {
	return h.renderPartial(c, "services", "services-rows", h.serviceViews())
}

// wizardError redirects the swap to the wizard's own error box (instead of
// the services table) via HTMX response headers, so a failed add doesn't
// clobber the existing rows.
func (h *Handler) wizardError(c echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#wizard-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
}

// AddService creates a new backend service from the add-service wizard.
// matchType picks which of host/prefix gets saved — the wizard only ever
// collects one of the two from the user. The backend must respond to a live
// reachability probe before it's saved — an unreachable backend is rejected.
func (h *Handler) AddService(c echo.Context) error {
	name := strings.TrimSpace(c.FormValue("name"))
	matchType := c.FormValue("match_type") // "host" | "prefix"
	matchValue := strings.TrimSpace(c.FormValue("match_value"))
	backend := strings.TrimSpace(c.FormValue("backend"))

	if name == "" || matchValue == "" || (matchType != "host" && matchType != "prefix") {
		return h.wizardError(c, "Please fill in all required fields.")
	}
	if err := services.Validate(backend); err != nil {
		return h.wizardError(c, err.Error())
	}
	if err := services.Probe(backend); err != nil {
		return h.wizardError(c, err.Error()+" — fix the backend or try again before adding.")
	}

	var host, prefix string
	if matchType == "host" {
		host = matchValue
	} else {
		prefix = matchValue
	}

	if err := h.db.AddService(name, host, prefix, backend); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	w := c.Response().Writer
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<div id="wizard-error" hx-swap-oob="true"></div>`)
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.serviceViews())
}

func (h *Handler) DeleteService(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveService(id); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.renderPartial(c, "services", "services-rows", h.serviceViews())
}

// ── Service TLS ───────────────────────────────────────────────────────────────

// tlsModalError redirects the swap to the TLS modal's own error box instead
// of the services table, mirroring wizardError for the add-service wizard.
func (h *Handler) tlsModalError(c echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#tls-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
}

// tlsSaved re-renders the services table after a TLS change, clears any
// stale error in the modal, and fires a "tls-saved" event (via HX-Trigger)
// that the modal listens for to close itself.
func (h *Handler) tlsSaved(c echo.Context) error {
	c.Response().Header().Set("HX-Trigger", "tls-saved")
	w := c.Response().Writer
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<div id="tls-error" hx-swap-oob="true"></div>`)
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.serviceViews())
}

// UploadServiceTLS saves an admin-provided cert+key PEM pair for a
// host-matched service. The private key is written to disk, never stored
// in the database (see services.SaveCustomCert).
func (h *Handler) UploadServiceTLS(c echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return h.tlsModalError(c, "service not found")
	}
	if svc.Host == "" {
		return h.tlsModalError(c, "TLS requires a host-matched service (this one matches by path prefix)")
	}

	certPEM := []byte(c.FormValue("cert_pem"))
	keyPEM := []byte(c.FormValue("key_pem"))
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return h.tlsModalError(c, "paste both the certificate and the private key")
	}

	certPath, keyPath, expiresAt, err := services.SaveCustomCert(svc.Name, certPEM, keyPEM)
	if err != nil {
		return h.tlsModalError(c, err.Error())
	}
	if err := h.db.SetServiceTLS(id, "custom", certPath, keyPath, expiresAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// EnableServiceAutoTLS marks a service for on-demand Let's Encrypt issuance.
// The actual certificate is obtained lazily by autocert on the first real
// HTTPS handshake for that domain — this just flips it on and reloads the
// registry's HostPolicy so that handshake is allowed to proceed.
func (h *Handler) EnableServiceAutoTLS(c echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return h.tlsModalError(c, "service not found")
	}
	if svc.Host == "" {
		return h.tlsModalError(c, "TLS requires a host-matched service (this one matches by path prefix)")
	}

	if err := h.db.SetServiceTLS(id, "auto", "", "", ""); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// ClearServiceTLS reverts a service to plain HTTP.
func (h *Handler) ClearServiceTLS(c echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	if err := h.db.ClearServiceTLS(id); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) render(c echo.Context, page string, data map[string]any) error {
	t, ok := h.tmpls[page]
	if !ok {
		return fmt.Errorf("template %q not found", page)
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Page"] = page
	headings := map[string]string{
		"dashboard": "Dashboard",
		"logs":      "Live Logs",
		"ip_rules":  "IP Rules",
		"geo_rules": "Geo Rules",
		"services":  "Services",
	}
	if _, ok := data["Heading"]; !ok {
		data["Heading"] = headings[page]
	}
	if _, ok := data["AdminPath"]; !ok {
		data["AdminPath"] = h.cfg.Admin.Path
	}
	if _, ok := data["AlertCount"]; !ok {
		data["AlertCount"] = h.unreadAlertCount()
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
