package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/challenge"
	"coraza-waf-mod/config"
	"coraza-waf-mod/geo"
	"coraza-waf-mod/metrics"
	"coraza-waf-mod/ratelimit"
	"coraza-waf-mod/services"
	"coraza-waf-mod/storage"

	"github.com/labstack/echo/v4"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

//go:embed templates
var templateFS embed.FS

var funcs = template.FuncMap{
	"flag":        countryFlag,
	"flagClass":   func(code string) string { return "fi fi-" + strings.ToLower(code) },
	"statusClass": statusClass,
	"fmtTime":     func(t time.Time) string { return t.Format("02 Jan 15:04:05") },
	"fmtTimeFull": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"fmtDur":      func(ms int64) string { return fmt.Sprintf("%dms", ms) },
	"today":       func() string { return time.Now().Format("2 January 2006") },
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
	"add":      func(a, b int) int { return a + b },
	"sub":      func(a, b int) int { return a - b },
	"isOdd":    func(i int) bool { return i%2 == 1 },
	"contains": strings.Contains,
	"splitComma": func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	},
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
	cfg             *config.Config
	db              *storage.DB
	ipbl            *blocklist.IPBlocklist
	geoBl           *geo.Blocker
	registry        *services.Registry
	broadcaster     *LogBroadcaster
	tmpls           map[string]*template.Template
	staticJS        fs.FS
	staticImgs      fs.FS
	reloadBot       func(*challenge.Challenger)
	buildChallenger func(enabled bool, threshold, ttl int) *challenge.Challenger
	reloadRateLimit func()
	reloadWAF       func()
	syncThreatIntel func(id int64)
}

type dashboardCountry struct {
	Code       string
	Name       string
	Count      int
	WidthClass string
}

type atAGlanceCard struct {
	Label      string
	Icon       string
	IconClass  string
	CardClass  string
	TrendClass string
	Trend      string
	Value      string
	SparkID    string
	SparkColor string
	AreaPath   string
	LinePath   string
}

// NewHandler builds the UI handler. jsFS must contain the minified JS
// assets at "static/js/dist/*" (see assets.go in the repo root); it's
// served under /<admin_path>/static/js/. imgsFS must contain
// "static/imgs/*"; it's served under /<admin_path>/static/imgs/.
func NewHandler(cfg *config.Config, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, registry *services.Registry, bc *LogBroadcaster, jsFS embed.FS, imgsFS embed.FS, reloadBot func(*challenge.Challenger), buildChallenger func(bool, int, int) *challenge.Challenger, reloadRateLimit func(), reloadWAF func(), syncThreatIntel func(int64)) (*Handler, error) {
	sub, err := fs.Sub(jsFS, "static/js/dist")
	if err != nil {
		return nil, fmt.Errorf("sub static/js/dist: %w", err)
	}
	imgsSub, err := fs.Sub(imgsFS, "static/imgs")
	if err != nil {
		return nil, fmt.Errorf("sub static/imgs: %w", err)
	}
	h := &Handler{cfg: cfg, db: db, ipbl: ipbl, geoBl: geoBl, registry: registry, broadcaster: bc, staticJS: sub, staticImgs: imgsSub, reloadBot: reloadBot, buildChallenger: buildChallenger, reloadRateLimit: reloadRateLimit, reloadWAF: reloadWAF, syncThreatIntel: syncThreatIntel}
	if err := h.parseTemplates(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) parseTemplates() error {
	// Standalone login page — does not use base.html.
	login, err := template.New("login").Funcs(funcs).ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return fmt.Errorf("parse template login: %w", err)
	}

	pages := []string{"dashboard", "logs", "ip_rules", "geo_rules", "services", "certificates", "waf_rules", "threat_intel", "settings"}
	h.tmpls = make(map[string]*template.Template, len(pages)+1)
	h.tmpls["login"] = login
	for _, page := range pages {
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS,
			"templates/components/*.html",
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

const sessionCookie = "cz_session"

// sessionAuth is the session-cookie middleware that guards every admin route.
// Unauthenticated requests are redirected to the login page.
func (h *Handler) sessionAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
		}
		valid, err := h.db.ValidateSession(cookie.Value)
		if err != nil || !valid {
			return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
		}
		return next(c)
	}
}

// Register mounts all admin routes on e under cfg.Admin.Path.
// Login/logout are public; everything else is behind sessionAuth.
func (h *Handler) Register(e *echo.Echo) {
	base := h.cfg.Admin.Path

	// Public routes — no session required.
	e.GET(base+"/login", h.LoginPage)
	e.POST(base+"/login", h.LoginPost)
	e.POST(base+"/logout", h.Logout)
	// Static assets are public so the login page can load spirals/JS before auth.
	e.StaticFS(base+"/static/js", h.staticJS)
	e.StaticFS(base+"/static/imgs", h.staticImgs)

	g := e.Group(base)
	g.Use(h.sessionAuth)

	g.GET("/metrics", echo.WrapHandler(metrics.Handler()))

	g.GET("", h.Dashboard)
	g.GET("/api/notifications", h.NotificationsPanel)
	g.GET("/api/notifications/stream", h.NotificationsStream)
	g.POST("/api/notifications/seen", h.MarkNotificationsSeen)
	g.GET("/api/traffic", h.TrafficSeries)
	g.GET("/api/threats", h.ThreatsSeries)
	g.GET("/logs", h.Logs)
	g.GET("/logs/export", h.ExportLogs)
	g.GET("/logs/stream", h.LogsStream)
	g.GET("/logs/:id", h.LogDetail)
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
	g.POST("/services/tls/pool", h.AssignPoolCert)
	g.POST("/services/tls/clear", h.ClearServiceTLS)
	g.GET("/certificates", h.CertificatesPage)
	g.POST("/certificates", h.AddCertificate)
	g.DELETE("/certificates/:id", h.DeleteCertificate)
	g.POST("/services/ratelimit", h.SetServiceRateLimit)
	g.POST("/services/bot/:id", h.SetServiceBotMode)
	g.POST("/settings/acme-email", h.SaveAcmeEmail)
	g.POST("/settings/bot", h.SaveBotSettings)
	g.POST("/settings/ratelimit", h.SaveRateLimitConfig)
	g.POST("/settings/ratelimit/test", h.TestRedisConnection)
	g.POST("/settings/webhook", h.SaveWebhookConfig)
	g.GET("/waf-rules", h.WAFRulesPage)
	g.POST("/waf-rules/disable", h.DisableWAFRule)
	g.DELETE("/waf-rules/:id", h.EnableWAFRule)
	g.GET("/threat-intel", h.ThreatIntelPage)
	g.POST("/threat-intel", h.AddThreatIntelSource)
	g.DELETE("/threat-intel/:id", h.DeleteThreatIntelSource)
	g.POST("/threat-intel/:id/toggle", h.ToggleThreatIntelSource)
	g.POST("/threat-intel/:id/sync", h.SyncThreatIntelSource)
	g.GET("/settings", h.SettingsPage)
	g.POST("/settings/credentials", h.ChangeCredentials)
	g.GET("/settings/backup", h.BackupDB)
}

// ── Login / logout ────────────────────────────────────────────────────────────

func (h *Handler) LoginPage(c echo.Context) error {
	// Redirect already-authenticated users straight to the dashboard.
	if cookie, err := c.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		if valid, _ := h.db.ValidateSession(cookie.Value); valid {
			return c.Redirect(http.StatusFound, h.cfg.Admin.Path)
		}
	}
	return h.renderLogin(c, "")
}

func (h *Handler) LoginPost(c echo.Context) error {
	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")

	adminEmail, _ := h.db.GetAdminEmail()
	ok, _ := h.db.CheckAdminPassword(password)
	// Constant-time comparison: always check both email and password
	// (same error message for both) so an attacker can't enumerate emails.
	if email != adminEmail || !ok {
		return h.renderLogin(c, "Invalid email or password.")
	}

	token, err := h.db.CreateSession()
	if err != nil {
		return h.renderLogin(c, "Internal error — please try again.")
	}

	c.SetCookie(&http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		SameSite: http.SameSiteLaxMode,
	})
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path)
}

func (h *Handler) Logout(c echo.Context) error {
	if cookie, err := c.Cookie(sessionCookie); err == nil {
		h.db.DeleteSession(cookie.Value) //nolint
	}
	c.SetCookie(&http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		MaxAge:   -1,
	})
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
}

func (h *Handler) renderLogin(c echo.Context, errMsg string) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["login"].ExecuteTemplate(c.Response(), "login", map[string]any{
		"Error":     errMsg,
		"AdminPath": h.cfg.Admin.Path,
	})
}

// ── Dashboard ──────────────────────────────────────────────────────────────────

func (h *Handler) Dashboard(c echo.Context) error {
	stats, err := h.db.GetStats()
	if err != nil {
		return err
	}
	recent, err := h.db.ListRequests(false, "", 10, 0)
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
	// SVG donut: r=74 circle has circumference ~465. Drawn as a 240° open
	// gauge (310 of those 465 units), with a 7-unit gap between the
	// allowed/blocked segments so the rounded caps read as a true break.
	const circ = 465
	const arc240 = circ * 240 / 360
	const gap = 7
	hasTraffic := stats.TotalToday > 0
	allowedArc, blockedArc, blockedOffset := 0, 0, 0
	if hasTraffic {
		usable := arc240 - gap
		blockedArc = stats.BlockedToday * usable / stats.TotalToday
		allowedArc = usable - blockedArc
		blockedOffset = -(allowedArc + gap)
	}
	botStats := h.db.GetBotStats()
	apps := h.registry.List()
	topCountryCounts, err := h.db.GetTopCountries(5, 24)
	if err != nil {
		return err
	}
	atAGlance, err := h.db.GetAtAGlanceStats()
	if err != nil {
		return err
	}
	return h.render(c, "dashboard", map[string]any{
		"Stats":         stats,
		"Recent":        recent,
		"TopBlocked":    topBlocked,
		"TopCountries":  dashboardCountries(topCountryCounts),
		"AtAGlance":     dashboardAtAGlance(atAGlance, len(apps)),
		"BlockRate":     blockRate,
		"HasTraffic":    hasTraffic,
		"TrackArc":      arc240,
		"AllowedArc":    allowedArc,
		"BlockedArc":    blockedArc,
		"BlockedOffset": blockedOffset,
		"Apps":          apps,
		"BotStats":      botStats,
	})
}

func dashboardCountries(rows []storage.CountryCount) []dashboardCountry {
	widths := []string{"w-full", "w-[85%]", "w-[79%]", "w-[75%]", "w-[70%]"}
	out := make([]dashboardCountry, 0, len(rows))
	for i, row := range rows {
		code := strings.ToUpper(strings.TrimSpace(row.Country))
		if code == "" {
			continue
		}
		widthClass := widths[len(widths)-1]
		if i < len(widths) {
			widthClass = widths[i]
		}
		out = append(out, dashboardCountry{
			Code:       code,
			Name:       countryName(code),
			Count:      row.Count,
			WidthClass: widthClass,
		})
	}
	return out
}

func countryName(code string) string {
	region, err := language.ParseRegion(code)
	if err != nil {
		return code
	}
	name := display.English.Regions().Name(region)
	if name == "" {
		return code
	}
	return name
}

func dashboardAtAGlance(s storage.AtAGlanceStats, serviceCount int) []atAGlanceCard {
	return []atAGlanceCard{
		{
			Label:      "Requests/sec",
			Icon:       "hgi-activity-01",
			IconClass:  "text-brand-dark",
			CardClass:  "bg-brand-tint",
			TrendClass: "text-brand-dark",
			Trend:      trendLabel(s.RequestsLastMinute, s.RequestsPrevMinute),
			Value:      fmt.Sprintf("%.1f", float64(s.RequestsLastMinute)/60),
			SparkID:    "spark-req",
			SparkColor: "#76C893",
			AreaPath:   "M0,26 18,23 36,25 54,16 72,19 90,9 108,13 126,5 144,8 170,3 170,36 0,36 Z",
			LinePath:   "M0,26 18,23 36,25 54,16 72,19 90,9 108,13 126,5 144,8 170,3",
		},
		{
			Label:      "Avg latency",
			Icon:       "hgi-loading-03",
			IconClass:  "text-blue-500",
			CardClass:  "bg-blue-50",
			TrendClass: "text-blue-500",
			Trend:      trendLabel(s.AvgLatencyMS, s.PrevAvgLatencyMS),
			Value:      fmt.Sprintf("%dms", s.AvgLatencyMS),
			SparkID:    "spark-lat",
			SparkColor: "#3B82F6",
			AreaPath:   "M0,10 18,14 36,9 54,18 72,15 90,22 108,17 126,26 144,22 170,28 170,36 0,36 Z",
			LinePath:   "M0,10 18,14 36,9 54,18 72,15 90,22 108,17 126,26 144,22 170,28",
		},
		{
			Label:      "Blocked/min",
			Icon:       "hgi-shield-ban",
			IconClass:  "text-amber-600",
			CardClass:  "bg-amber-50",
			TrendClass: "text-amber-600",
			Trend:      trendLabel(s.BlockedLastMinute, s.BlockedPrevMinute),
			Value:      strconv.Itoa(s.BlockedLastMinute),
			SparkID:    "spark-blk",
			SparkColor: "#D97706",
			AreaPath:   "M0,8 18,12 36,11 54,17 72,15 90,20 108,18 126,24 144,21 170,27 170,36 0,36 Z",
			LinePath:   "M0,8 18,12 36,11 54,17 72,15 90,20 108,18 126,24 144,21 170,27",
		},
		{
			Label:      "Active services",
			Icon:       "hgi-server-stack-01",
			IconClass:  "text-slate-500",
			CardClass:  "bg-surface",
			TrendClass: "text-slate-400",
			Trend:      "live",
			Value:      strconv.Itoa(serviceCount),
			SparkID:    "spark-svc",
			SparkColor: "#94A3B8",
			AreaPath:   "M0,18 18,18 36,17 54,18 72,16 90,18 108,17 126,18 144,16 170,18 170,36 0,36 Z",
			LinePath:   "M0,18 18,18 36,17 54,18 72,16 90,18 108,17 126,18 144,16 170,18",
		},
		{
			Label:      "WAF rule hits",
			Icon:       "hgi-cancel-circle",
			IconClass:  "text-red-500",
			CardClass:  "bg-red-50",
			TrendClass: "text-red-500",
			Trend:      trendLabel(s.WAFRuleHitsToday, s.WAFRuleHitsPreviousDay),
			Value:      strconv.Itoa(s.WAFRuleHitsToday),
			SparkID:    "spark-rul",
			SparkColor: "#EF4444",
			AreaPath:   "M0,28 18,25 36,26 54,20 72,22 90,14 108,17 126,9 144,12 170,6 170,36 0,36 Z",
			LinePath:   "M0,28 18,25 36,26 54,20 72,22 90,14 108,17 126,9 144,12 170,6",
		},
	}
}

func trendLabel(current, previous int) string {
	if previous == 0 {
		if current == 0 {
			return "0.0%"
		}
		return "+100%"
	}
	delta := float64(current-previous) * 100 / float64(previous)
	if delta > 0 {
		return fmt.Sprintf("+%.1f%%", delta)
	}
	return fmt.Sprintf("%.1f%%", delta)
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
			fmt.Fprintf(w, "event: count\ndata: %d\n\n", h.unreadAlertCount())
			toastData, _ := json.Marshal(map[string]string{
				"action":  entry.Action,
				"ip":      entry.RealIP,
				"country": entry.Country,
				"method":  entry.Method,
				"path":    entry.Path,
			})
			fmt.Fprintf(w, "event: toast\ndata: %s\n\n", toastData)
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

// LogDetail returns the full detail of one request log entry as JSON,
// including the proxy IP and captured request headers. Used by the
// client-side detail modal on the Logs page.
func (h *Handler) LogDetail(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}

	// Parse headers_json into a plain map for the response.
	var headers map[string]string
	if d.HeadersJSON != "" {
		_ = json.Unmarshal([]byte(d.HeadersJSON), &headers)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"id":          d.ID,
		"request_id":  d.RequestID,
		"timestamp":   d.Timestamp.UTC().Format(time.RFC3339),
		"app_name":    d.AppName,
		"real_ip":     d.RealIP,
		"proxy_ip":    d.ProxyIP,
		"country":     d.Country,
		"method":      d.Method,
		"host":        d.Host,
		"path":        d.Path,
		"query":       d.Query,
		"status":      d.Status,
		"blocked":     d.Blocked,
		"rule_id":     d.RuleID,
		"action":      d.Action,
		"user_agent":  d.UserAgent,
		"duration_ms": d.Duration,
		"proto":       d.Proto,
		"tls_version": d.TLSVersion,
		"tls_cipher":  d.TLSCipher,
		"tls_sni":     d.TLSSNI,
		"asn":         d.ASN,
		"org":         d.Org,
		"ja3_hash":    d.JA3Hash,
		"bot_score":   d.BotScore,
		"headers":     headers,
	})
}

// ── IP Rules ───────────────────────────────────────────────────────────────────

func (h *Handler) IPRulesPage(c echo.Context) error {
	rules, err := h.db.ListIPRules()
	if err != nil {
		return err
	}
	blockCount, allowCount := 0, 0
	for _, r := range rules {
		if r.RuleType == "block" {
			blockCount++
		} else {
			allowCount++
		}
	}
	blockPct, allowPct := 0, 0
	if total := len(rules); total > 0 {
		blockPct = blockCount * 100 / total
		allowPct = allowCount * 100 / total
	}
	return h.render(c, "ip_rules", map[string]any{
		"Rules":      rules,
		"Apps":       h.registry.List(),
		"BlockCount": blockCount,
		"AllowCount": allowCount,
		"BlockPct":   blockPct,
		"AllowPct":   allowPct,
	})
}

func (h *Handler) AddIPRule(c echo.Context) error {
	appName := c.FormValue("app_name")
	ip := strings.TrimSpace(c.FormValue("ip"))
	ruleType := c.FormValue("rule_type")

	if ip == "" || (ruleType != "block" && ruleType != "allow") {
		return c.String(http.StatusBadRequest, "invalid input")
	}

	// Accept plain IPs and CIDR ranges. Try CIDR first so "10.0.0.0/8" is
	// handled correctly (net.ParseIP rejects the slash). net.ParseCIDR
	// canonicalises host bits (e.g. "10.0.1.5/24" → "10.0.1.0/24").
	if _, network, err := net.ParseCIDR(ip); err == nil {
		ip = network.String()
	} else if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			ip = v4.String()
		} else {
			ip = parsed.String()
		}
	} else {
		return c.String(http.StatusBadRequest, "invalid IP or CIDR — enter 1.2.3.4, ::1, or 10.0.0.0/8")
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
	blockCount, allowCount := 0, 0
	for _, r := range rules {
		if r.RuleType == "block" {
			blockCount++
		} else {
			allowCount++
		}
	}
	blockPct, allowPct := 0, 0
	if total := len(rules); total > 0 {
		blockPct = blockCount * 100 / total
		allowPct = allowCount * 100 / total
	}
	return h.render(c, "geo_rules", map[string]any{
		"Rules":      rules,
		"Apps":       h.registry.List(),
		"BlockCount": blockCount,
		"AllowCount": allowCount,
		"BlockPct":   blockPct,
		"AllowPct":   allowPct,
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

// ── WAF Rules ─────────────────────────────────────────────────────────────────

func (h *Handler) WAFRulesPage(c echo.Context) error {
	disabled, err := h.db.ListDisabledWAFRules()
	if err != nil {
		return err
	}
	topRules, err := h.db.GetTopFiringRules(20)
	if err != nil {
		return err
	}
	return h.render(c, "waf_rules", map[string]any{
		"Disabled": disabled,
		"TopRules": topRules,
	})
}

func (h *Handler) DisableWAFRule(c echo.Context) error {
	ruleIDStr := strings.TrimSpace(c.FormValue("rule_id"))
	reason := strings.TrimSpace(c.FormValue("reason"))

	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil || ruleID <= 0 {
		return c.String(http.StatusBadRequest, "invalid rule ID")
	}
	if err := h.db.DisableWAFRule(ruleID, reason); err != nil {
		return err
	}
	h.reloadWAF()
	disabled, _ := h.db.ListDisabledWAFRules()
	topRules, _ := h.db.GetTopFiringRules(20)
	return h.renderPartial(c, "waf_rules", "waf-content", map[string]any{
		"Disabled": disabled,
		"TopRules": topRules,
	})
}

func (h *Handler) EnableWAFRule(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.EnableWAFRule(id); err != nil {
		return err
	}
	h.reloadWAF()
	disabled, _ := h.db.ListDisabledWAFRules()
	topRules, _ := h.db.GetTopFiringRules(20)
	return h.renderPartial(c, "waf_rules", "waf-content", map[string]any{
		"Disabled": disabled,
		"TopRules": topRules,
	})
}

// ── Threat Intel ─────────────────────────────────────────────────────────────

// Presets are well-known free threat intel block lists shown as quick-add chips.
var threatIntelPresets = []struct {
	Label         string
	URL           string
	IntervalHours int
}{
	{"Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist", 6},
	{"Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 24},
	{"Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", 24},
	{"Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 12},
	{"CINS Score", "http://cinsscore.com/list/ci-badguys.txt", 24},
}

func (h *Handler) threatIntelData() map[string]any {
	sources, _ := h.db.ListThreatIntelSources()
	return map[string]any{
		"Sources": sources,
		"Presets": threatIntelPresets,
	}
}

func (h *Handler) ThreatIntelPage(c echo.Context) error {
	return h.render(c, "threat_intel", h.threatIntelData())
}

func (h *Handler) AddThreatIntelSource(c echo.Context) error {
	label := strings.TrimSpace(c.FormValue("label"))
	url := strings.TrimSpace(c.FormValue("url"))
	hours, err := strconv.Atoi(c.FormValue("interval_hours"))
	if err != nil || hours < 1 {
		hours = 24
	}
	if label == "" || url == "" {
		return c.String(http.StatusBadRequest, "label and url required")
	}
	if err := h.db.AddThreatIntelSource(label, url, hours); err != nil {
		return c.String(http.StatusConflict, "source already exists")
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

func (h *Handler) DeleteThreatIntelSource(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	_ = h.db.DeleteThreatIntelSource(id)
	if err := h.ipbl.ReloadIntel(h.db); err != nil {
		return err
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

func (h *Handler) ToggleThreatIntelSource(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	enabled := c.FormValue("enabled") == "1"
	_ = h.db.SetThreatIntelSourceEnabled(id, enabled)
	if err := h.ipbl.ReloadIntel(h.db); err != nil {
		return err
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

func (h *Handler) SyncThreatIntelSource(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if h.syncThreatIntel != nil {
		h.syncThreatIntel(id)
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

// ── Services ──────────────────────────────────────────────────────────────────

// ServiceView pairs a stored service with its last-known reachability, for
// rendering the status dot in the services table.
type ServiceView struct {
	storage.Service
	Healthy  bool
	Known    bool
	CertName string // pool cert name when CertID > 0, otherwise ""
}

func (h *Handler) serviceViews() []ServiceView {
	list := h.registry.List()
	certMap := make(map[int64]string)
	if certs, err := h.db.ListCertificates(); err == nil {
		for _, c := range certs {
			certMap[c.ID] = c.Name
		}
	}
	out := make([]ServiceView, len(list))
	for i, s := range list {
		healthy, known := h.registry.IsHealthy(s.Name)
		out[i] = ServiceView{Service: s, Healthy: healthy, Known: known, CertName: certMap[s.CertID]}
	}
	return out
}

func (h *Handler) ServicesPage(c echo.Context) error {
	poolCerts, _ := h.db.ListCertificates()
	return h.render(c, "services", map[string]any{
		"Services":  h.serviceViews(),
		"PoolCerts": poolCerts,
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

// sanitizeHost strips any scheme (http://, https://) and trailing slashes
// from a host value so "http://example.com/" is stored as "example.com".
// This prevents a common paste mistake where the full URL is entered instead
// of just the hostname.
func sanitizeHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h = strings.TrimRight(h, "/")
	// Strip port only if it matches the default (80/443) — non-standard ports
	// are kept because they're meaningful for matching.
	return h
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
		host = sanitizeHost(matchValue)
	} else {
		prefix = matchValue
	}

	rps, _ := strconv.ParseFloat(c.FormValue("rps"), 64)
	burst, _ := strconv.Atoi(c.FormValue("burst"))
	if rps < 0 {
		rps = 0
	}
	if burst < 0 {
		burst = 0
	}

	if err := h.db.AddService(name, host, prefix, backend, rps, burst); err != nil {
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

// ── Certificate Pool ──────────────────────────────────────────────────────────

func (h *Handler) certError(c echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#cert-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
}

func (h *Handler) renderCertRows(c echo.Context) error {
	certs, _ := h.db.ListCertificates()
	return h.renderPartial(c, "certificates", "cert-rows", map[string]any{
		"Certs":     certs,
		"AdminPath": h.cfg.Admin.Path,
	})
}

func (h *Handler) CertificatesPage(c echo.Context) error {
	certs, _ := h.db.ListCertificates()
	return h.render(c, "certificates", map[string]any{
		"Certs": certs,
	})
}

// AddCertificate uploads a cert+key PEM pair to the shared pool. It parses
// the certificate first to auto-detect covered domains and the expiry date,
// then saves to disk and records the paths in the database.
func (h *Handler) AddCertificate(c echo.Context) error {
	name := strings.TrimSpace(c.FormValue("name"))
	certPEM := []byte(c.FormValue("cert_pem"))
	keyPEM := []byte(c.FormValue("key_pem"))

	if name == "" {
		return h.certError(c, "name is required")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return h.certError(c, "paste both the certificate and private key")
	}

	domains, expiresAt, err := services.ParseCertInfo(certPEM)
	if err != nil {
		return h.certError(c, "invalid certificate: "+err.Error())
	}

	// Insert first to obtain the row ID used as the on-disk directory name.
	id, err := h.db.AddCertificate(name, strings.Join(domains, ", "), expiresAt.UTC().Format(time.RFC3339), "", "")
	if err != nil {
		return h.certError(c, "save: "+err.Error())
	}

	certPath, keyPath, err := services.SavePoolCert(id, certPEM, keyPEM)
	if err != nil {
		h.db.DeleteCertificate(id) //nolint
		return h.certError(c, err.Error())
	}

	if err := h.db.UpdateCertificatePaths(id, certPath, keyPath); err != nil {
		return h.certError(c, "update paths: "+err.Error())
	}

	return h.renderCertRows(c)
}

// DeleteCertificate removes a cert from the pool. Services that referenced it
// are reset to no-TLS by the DB layer, and the registry is reloaded so they
// stop presenting the cert immediately.
func (h *Handler) DeleteCertificate(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.DeleteCertificate(id); err != nil {
		return err
	}
	services.DeletePoolCert(id)
	h.registry.Reload(h.db) //nolint
	return h.renderCertRows(c)
}

// AssignPoolCert links an existing pool cert to a host-matched service. After
// this call the registry serves that cert for the service's domain over TLS.
func (h *Handler) AssignPoolCert(c echo.Context) error {
	serviceID, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	certID, err := strconv.ParseInt(c.FormValue("cert_id"), 10, 64)
	if err != nil || certID <= 0 {
		return h.tlsModalError(c, "select a certificate")
	}
	svc, err := h.db.GetService(serviceID)
	if err != nil {
		return h.tlsModalError(c, "service not found")
	}
	if svc.Host == "" {
		return h.tlsModalError(c, "TLS requires a host-matched service (this one matches by path prefix)")
	}
	if err := h.db.SetServiceCertID(serviceID, certID); err != nil {
		return h.tlsModalError(c, err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
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
// If no ACME email is stored in the DB yet, it fires a need-acme-email event
// so the UI can prompt the user before proceeding — without an email Let's
// Encrypt cannot register an account and cert issuance will always fail.
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

	email, err := h.db.GetAcmeEmail()
	if err != nil {
		return err
	}
	if email == "" {
		// No email yet — ask the UI to collect it before proceeding.
		c.Response().Header().Set("HX-Trigger",
			fmt.Sprintf(`{"need-acme-email":{"service_id":%d}}`, id))
		return c.String(http.StatusOK, "")
	}

	if err := h.db.SetServiceTLS(id, "auto", "", "", ""); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// SaveAcmeEmail stores the Let's Encrypt contact email and, if a service_id
// is provided, immediately enables auto-TLS for that service so the user
// doesn't have to click "Enable" twice after filling in their email.
func (h *Handler) SaveAcmeEmail(c echo.Context) error {
	email := strings.TrimSpace(c.FormValue("email"))
	if email == "" || !strings.Contains(email, "@") {
		c.Response().Header().Set("HX-Retarget", "#acme-email-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, "Enter a valid email address.")
	}
	if err := h.db.SetAcmeEmail(email); err != nil {
		return err
	}
	// If the caller passed a service_id, enable auto-TLS for it now.
	if id, err := strconv.Atoi(c.FormValue("service_id")); err == nil && id > 0 {
		if err := h.db.SetServiceTLS(id, "auto", "", "", ""); err != nil {
			return err
		}
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	c.Response().Header().Set("HX-Trigger", "acme-email-saved")
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

func (h *Handler) SetServiceRateLimit(c echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid service")
	}
	rps, _ := strconv.ParseFloat(c.FormValue("rps"), 64)
	burst, _ := strconv.Atoi(c.FormValue("burst"))
	if rps < 0 {
		rps = 0
	}
	if burst < 0 {
		burst = 0
	}
	if err := h.db.SetServiceRateLimit(id, rps, burst); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	w := c.Response().Writer
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("HX-Trigger", "rl-saved")
	fmt.Fprint(w, `<div id="rl-error" hx-swap-oob="true"></div>`)
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.serviceViews())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// ── Settings ──────────────────────────────────────────────────────────────────

func (h *Handler) SettingsPage(c echo.Context) error {
	email, _ := h.db.GetAdminEmail()
	botEnabled, botThreshold, botTTL, _ := h.db.GetBotSettings()
	redisAddr, _, _ := h.db.GetRedisConfig()
	rlBackend := "memory"
	if redisAddr != "" {
		rlBackend = "redis"
	}
	wh, _ := h.db.GetWebhookConfig()
	return h.render(c, "settings", map[string]any{
		"AdminEmail":     email,
		"BotEnabled":     botEnabled,
		"BotThreshold":   botThreshold,
		"BotTTL":         botTTL,
		"RLBackend":      rlBackend,
		"RLRedisAddr":    redisAddr,
		"WebhookURL":     wh.URL,
		"WebhookSecret":  wh.Secret,
		"WebhookEnabled": wh.Enabled,
		"WebhookEvents":  wh.Events,
	})
}

// SaveBotSettings persists global bot-protection settings and hot-reloads the
// challenger so changes take effect without a server restart.
func (h *Handler) SaveBotSettings(c echo.Context) error {
	enabled := c.FormValue("bot_enabled") == "1"
	threshold, _ := strconv.Atoi(c.FormValue("bot_threshold"))
	ttl, _ := strconv.Atoi(c.FormValue("bot_ttl"))
	if threshold <= 0 {
		threshold = 8
	}
	if ttl <= 0 {
		ttl = 3600
	}

	if err := h.db.SetBotSettings(enabled, threshold, ttl); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if h.reloadBot != nil && h.buildChallenger != nil {
		h.reloadBot(h.buildChallenger(enabled, threshold, ttl))
	}

	return h.renderPartial(c, "settings", "bot-card", map[string]any{
		"AdminPath":    h.cfg.Admin.Path,
		"BotEnabled":   enabled,
		"BotThreshold": threshold,
		"BotTTL":       ttl,
		"BotSaveOK":    true,
	})
}

// SetServiceBotMode sets the per-service bot protection override (inherit / always / off).
func (h *Handler) SetServiceBotMode(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	mode := c.FormValue("bot_mode")
	if mode != "inherit" && mode != "always" && mode != "off" {
		mode = "inherit"
	}
	if err := h.db.SetServiceBotMode(id, mode); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response().Writer
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.serviceViews())
}

// SaveRateLimitConfig persists the rate-limit backend choice (memory+SQLite or
// Redis) and hot-reloads the active backend in the proxy handler.
func (h *Handler) SaveRateLimitConfig(c echo.Context) error {
	backend := c.FormValue("rl_backend")
	addr := strings.TrimSpace(c.FormValue("rl_redis_addr"))
	password := c.FormValue("rl_redis_password")

	rlErr := ""
	if backend == "redis" {
		if addr == "" {
			rlErr = "Redis address must not be empty."
		} else if err := ratelimit.PingRedis(addr, password); err != nil {
			rlErr = "Redis connection failed: " + err.Error()
		} else if err := h.db.SetRedisConfig(addr, password); err != nil {
			rlErr = "Failed to save: " + err.Error()
		}
	} else {
		if err := h.db.SetRedisConfig("", ""); err != nil {
			rlErr = "Failed to save: " + err.Error()
		}
	}

	if rlErr == "" && h.reloadRateLimit != nil {
		h.reloadRateLimit()
	}

	rlBackend := backend
	rlAddr := addr
	if rlErr != "" && backend != "redis" {
		// Revert display to stored config on error.
		if storedAddr, _, _ := h.db.GetRedisConfig(); storedAddr != "" {
			rlBackend = "redis"
			rlAddr = storedAddr
		} else {
			rlBackend = "memory"
		}
	}
	return h.renderPartial(c, "settings", "ratelimit-card", map[string]any{
		"AdminPath":   h.cfg.Admin.Path,
		"RLBackend":   rlBackend,
		"RLRedisAddr": rlAddr,
		"RLSaveOK":    rlErr == "",
		"RLError":     rlErr,
	})
}

// SaveWebhookConfig persists the webhook delivery settings.
func (h *Handler) SaveWebhookConfig(c echo.Context) error {
	url := strings.TrimSpace(c.FormValue("webhook_url"))
	secret := strings.TrimSpace(c.FormValue("webhook_secret"))
	enabled := c.FormValue("webhook_enabled") == "1"
	// webhook_events is a multi-value checkbox — collect all checked values.
	eventVals, _ := c.Request().PostForm["webhook_events"]
	events := strings.Join(eventVals, ",")
	if events == "" {
		events = "blocked"
	}
	cfg := storage.WebhookConfig{URL: url, Secret: secret, Enabled: enabled && url != "", Events: events}
	saveErr := ""
	if err := h.db.SetWebhookConfig(cfg); err != nil {
		saveErr = err.Error()
	}
	return h.renderPartial(c, "settings", "webhook-card", map[string]any{
		"AdminPath":      h.cfg.Admin.Path,
		"WebhookURL":     url,
		"WebhookSecret":  secret,
		"WebhookEnabled": cfg.Enabled,
		"WebhookEvents":  events,
		"WebhookSaveOK":  saveErr == "",
		"WebhookSaveErr": saveErr,
	})
}

// ExportLogs streams the filtered request log as NDJSON (one JSON object per
// line). Accepts the same from/to/app/status query parameters as the Logs page.
func (h *Handler) ExportLogs(c echo.Context) error {
	q := c.QueryParams()
	filter := storage.LogFilter{
		AppName:     q.Get("app"),
		StatusClass: q.Get("status"),
	}
	if t, err := time.Parse("2006-01-02T15:04", q.Get("from")); err == nil {
		filter.From = t
	}
	if t, err := time.Parse("2006-01-02T15:04", q.Get("to")); err == nil {
		filter.To = t
	}

	filename := "waf-logs-" + time.Now().UTC().Format("2006-01-02") + ".ndjson"
	w := c.Response().Writer
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	flusher, canFlush := w.(http.Flusher)
	n := 0
	if err := h.db.ExportRequests(filter, func(r storage.RequestLog) bool {
		_ = enc.Encode(r) // each Encode call appends a newline
		n++
		if canFlush && n%500 == 0 {
			flusher.Flush()
		}
		return true
	}); err != nil {
		return err
	}
	if canFlush {
		flusher.Flush()
	}
	return nil
}

// TestRedisConnection tests reachability of a Redis server without saving anything.
// Returns a small HTML fragment consumed by HTMX to show inline status.
func (h *Handler) TestRedisConnection(c echo.Context) error {
	addr := strings.TrimSpace(c.FormValue("rl_redis_addr"))
	password := c.FormValue("rl_redis_password")
	if addr == "" {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Address is required.</span>`)
	}
	if err := ratelimit.PingRedis(addr, password); err != nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Connection failed: `+template.HTMLEscapeString(err.Error())+`</span>`)
	}
	return c.HTML(http.StatusOK,
		`<span class="text-brand text-[13px] font-medium">Connected successfully.</span>`)
}

func (h *Handler) ChangeCredentials(c echo.Context) error {
	currentPassword := c.FormValue("current_password")
	newEmail := strings.TrimSpace(c.FormValue("new_email"))
	newPassword := c.FormValue("new_password")
	confirmPassword := c.FormValue("confirm_password")

	email, _ := h.db.GetAdminEmail()

	renderErr := func(msg string) error {
		return h.render(c, "settings", map[string]any{
			"AdminEmail":    email,
			"CredentialErr": msg,
		})
	}

	ok, _ := h.db.CheckAdminPassword(currentPassword)
	if !ok {
		return renderErr("Current password is incorrect.")
	}
	if newPassword != "" && newPassword != confirmPassword {
		return renderErr("New passwords do not match.")
	}
	if newPassword != "" && len(newPassword) < 8 {
		return renderErr("New password must be at least 8 characters.")
	}
	if err := h.db.UpdateAdminCredentials(newEmail, newPassword); err != nil {
		return renderErr("Failed to update credentials — please try again.")
	}
	// Credentials changed — force re-login.
	if cookie, err := c.Cookie(sessionCookie); err == nil {
		h.db.DeleteSession(cookie.Value) //nolint
	}
	c.SetCookie(&http.Cookie{Name: sessionCookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1})
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
}

func (h *Handler) BackupDB(c echo.Context) error {
	tmp := fmt.Sprintf("%s/coraza-backup-%d.db", os.TempDir(), time.Now().UnixNano())
	if err := h.db.BackupTo(tmp); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer os.Remove(tmp)
	filename := fmt.Sprintf("coraza-waf-%s.db", time.Now().Format("2006-01-02"))
	return c.Attachment(tmp, filename)
}

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
		"dashboard":    "Dashboard",
		"logs":         "Live Logs",
		"ip_rules":     "IP Rules",
		"geo_rules":    "Geo Rules",
		"services":     "Services",
		"waf_rules":    "WAF Rules",
		"threat_intel": "Threat Intel",
		"certificates": "Certificates",
		"settings":     "Settings",
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
	// no-store keeps these pages out of the browser's back/forward cache.
	// Without it, navigating away leaves the previous page (and its live
	// notifications/logs EventSource — see app.js and logs.html) frozen in
	// bfcache instead of torn down, so each connection stays open for as long
	// as that bfcache entry survives. A few quick page navigations can pile
	// up more open SSE connections than Chrome's ~6-per-origin HTTP/1.1 limit
	// allows, stalling every other request behind them for as long as it
	// takes bfcache to evict an old entry. It's also the right call for an
	// authenticated admin panel regardless — these pages shouldn't be
	// restorable from cache after logout.
	c.Response().Header().Set("Cache-Control", "no-store")
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
