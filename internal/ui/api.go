package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// apiKeyTouchThrottle bounds how often a successful auth writes last_used_at
// back to SQLite, so a scripted client hammering the API doesn't turn into
// a write per request on the single SQLite writer.
const apiKeyTouchThrottle = time.Minute

// newAPIKey generates a bearer token of the form "cwaf_<40 hex chars>"
// (160 bits of entropy from crypto/rand) plus the SHA-256 hex digest used
// for storage/lookup and a short, non-secret prefix used for display.
func newAPIKey() (raw, prefix, hash string, err error) {
	b := make([]byte, 20)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	raw = "cwaf_" + hex.EncodeToString(b)
	prefix = raw[:13] // "cwaf_" + 8 hex chars: enough to tell keys apart, not enough to guess
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, prefix, hash, nil
}

// apiKeyAuth authenticates /api/v1/* requests via "Authorization: Bearer
// <key>" instead of the session cookie. It never redirects (there's no login
// page for an API client to be sent to) and skips csrfProtect: a bearer
// token lives in a header, not a cookie, so CSRF doesn't apply to it.
func (h *Handler) apiKeyAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ip := h.clientIP(c.Request())
		if wait, locked := h.apiKeyLimiter.blocked(ip); locked {
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "too many failed attempts, retry in " + wait.Round(time.Second).String(),
			})
		}

		auth := c.Request().Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		token = strings.TrimSpace(token)
		if !ok || token == "" {
			if h.apiKeyLimiter.fail(ip) {
				return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts, try again later"})
			}
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing or invalid Authorization header"})
		}

		sum := sha256.Sum256([]byte(token))
		key, err := h.db.ValidateAPIKey(hex.EncodeToString(sum[:]))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if key == nil {
			if h.apiKeyLimiter.fail(ip) {
				return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts, try again later"})
			}
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
		}
		h.apiKeyLimiter.success(ip)

		if key.LastUsedAt == nil || time.Since(*key.LastUsedAt) > apiKeyTouchThrottle {
			id := key.ID
			go func() {
				if err := h.db.TouchAPIKey(id); err != nil {
					log.Printf("api key touch: %v", err)
				}
			}()
		}

		c.Set("api_key_id", key.ID)
		return next(c)
	}
}

// RegisterAPI mounts the bearer-token-authenticated REST API at
// {admin.path}/api/v1/*, as a sibling to (not nested inside) the
// session-cookie-authenticated group Register builds; see apiKeyAuth for
// why it skips sessionAuth/csrfProtect. hostGuard runs first, same as the
// admin UI group, so this API is likewise unreachable on a service's own
// domain (see hostGuard in handlers.go).
func (h *Handler) RegisterAPI(e *echo.Echo) {
	api := e.Group(h.cfg.Admin.Path + "/api/v1")
	api.Use(h.hostGuard, middleware.BodyLimit("1M"), h.apiKeyAuth)

	api.GET("/services", h.APIListServices)
	api.POST("/services", h.APICreateService)
	api.GET("/services/:id", h.APIGetService)
	api.PUT("/services/:id", h.APIUpdateService)
	api.DELETE("/services/:id", h.APIDeleteService)

	api.GET("/ip-rules", h.APIListIPRules)
	api.POST("/ip-rules", h.APICreateIPRule)
	api.DELETE("/ip-rules/:id", h.APIDeleteIPRule)

	api.GET("/bans", h.APIListBans)
	api.POST("/bans", h.APICreateBan)
	api.DELETE("/bans/:id", h.APIDeleteBan)
}

func apiError(c echo.Context, status int, msg string) error {
	return c.JSON(status, map[string]string{"error": msg})
}

// ── Services ─────────────────────────────────────────────────────────────────

func (h *Handler) APIListServices(c echo.Context) error {
	return c.JSON(http.StatusOK, h.registry.List())
}

func (h *Handler) APIGetService(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return apiError(c, http.StatusNotFound, "service not found")
	}
	return c.JSON(http.StatusOK, svc)
}

// apiCreateServiceRequest mirrors the fields accepted by the admin UI's
// service-add wizard (see AddService, ui/handlers.go).
type apiCreateServiceRequest struct {
	Name       string  `json:"name"`
	MatchType  string  `json:"match_type"` // "host" | "prefix"
	MatchValue string  `json:"match_value"`
	Backend    string  `json:"backend"`
	RPS        float64 `json:"rate_limit_rps"`
	Burst      int     `json:"rate_limit_burst"`
}

func (h *Handler) APICreateService(c echo.Context) error {
	var req apiCreateServiceRequest
	if err := c.Bind(&req); err != nil {
		return apiError(c, http.StatusBadRequest, "invalid JSON body")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.MatchValue = strings.TrimSpace(req.MatchValue)
	req.Backend = strings.TrimSpace(req.Backend)

	if req.Name == "" || req.MatchValue == "" || (req.MatchType != "host" && req.MatchType != "prefix") {
		return apiError(c, http.StatusBadRequest, "name, backend, match_type (host|prefix), and match_value are required")
	}
	if err := services.Validate(req.Backend); err != nil {
		return apiError(c, http.StatusBadRequest, err.Error())
	}
	if err := services.Probe(req.Backend); err != nil {
		return apiError(c, http.StatusBadRequest, err.Error()+". Fix the backend and try again.")
	}
	if req.RPS < 0 {
		req.RPS = 0
	}
	if req.Burst < 0 {
		req.Burst = 0
	}

	var host, prefix string
	if req.MatchType == "host" {
		host = sanitizeHost(req.MatchValue)
	} else {
		prefix = req.MatchValue
	}

	if err := h.db.AddService(req.Name, host, prefix, req.Backend, req.RPS, req.Burst); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}

	for _, svc := range h.registry.List() {
		if svc.Name == req.Name {
			return c.JSON(http.StatusCreated, svc)
		}
	}
	return c.NoContent(http.StatusCreated)
}

// apiUpdateServiceRequest updates the core service fields (mirroring
// storage.DB.UpdateService) plus optional per-service overrides. Pointer
// fields distinguish "omitted" from "explicitly cleared" so a partial
// payload never silently zeroes settings the caller didn't mention.
type apiUpdateServiceRequest struct {
	Name    *string  `json:"name"`
	Host    *string  `json:"host"`
	Prefix  *string  `json:"prefix"`
	Backend *string  `json:"backend"`
	RPS     *float64 `json:"rate_limit_rps"`
	Burst   *int     `json:"rate_limit_burst"`
	BotMode *string  `json:"bot_mode"` // "inherit" | "always" | "off"
}

func (h *Handler) APIUpdateService(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	existing, err := h.db.GetService(id)
	if err != nil {
		return apiError(c, http.StatusNotFound, "service not found")
	}

	var req apiUpdateServiceRequest
	if err := c.Bind(&req); err != nil {
		return apiError(c, http.StatusBadRequest, "invalid JSON body")
	}

	name, host, prefix, backend := existing.Name, existing.Host, existing.Prefix, existing.Backend
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.Host != nil {
		host = sanitizeHost(strings.TrimSpace(*req.Host))
	}
	if req.Prefix != nil {
		prefix = strings.TrimSpace(*req.Prefix)
	}
	if req.Backend != nil {
		backend = strings.TrimSpace(*req.Backend)
		if err := services.Validate(backend); err != nil {
			return apiError(c, http.StatusBadRequest, err.Error())
		}
	}
	if name == "" || backend == "" {
		return apiError(c, http.StatusBadRequest, "name and backend cannot be empty")
	}

	if err := h.db.UpdateService(id, name, host, prefix, backend); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if req.RPS != nil || req.Burst != nil {
		rps, burst := existing.RateLimitRPS, existing.RateLimitBurst
		if req.RPS != nil {
			rps = *req.RPS
		}
		if req.Burst != nil {
			burst = *req.Burst
		}
		if err := h.db.SetServiceRateLimit(id, rps, burst); err != nil {
			return apiError(c, http.StatusInternalServerError, err.Error())
		}
	}
	if req.BotMode != nil {
		mode := *req.BotMode
		if mode != "inherit" && mode != "always" && mode != "off" {
			return apiError(c, http.StatusBadRequest, "bot_mode must be inherit, always, or off")
		}
		if err := h.db.SetServiceBotMode(id, mode); err != nil {
			return apiError(c, http.StatusInternalServerError, err.Error())
		}
	}

	if err := h.registry.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, svc)
}

func (h *Handler) APIDeleteService(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveService(id); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.NoContent(http.StatusNoContent)
}

// ── IP rules ─────────────────────────────────────────────────────────────────

// normalizeIPOrCIDR accepts a plain IP or CIDR range and returns its
// canonical string form, the same normalization AddIPRule (ui/handlers.go)
// applies, kept here so both the HTMX and REST paths agree on stored form.
func normalizeIPOrCIDR(ip string) (string, error) {
	if _, network, err := net.ParseCIDR(ip); err == nil {
		return network.String(), nil
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String(), nil
		}
		return parsed.String(), nil
	}
	return "", &net.ParseError{Type: "IP address or CIDR", Text: ip}
}

func (h *Handler) APIListIPRules(c echo.Context) error {
	rules, err := h.db.ListIPRules()
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, rules)
}

type apiIPRuleRequest struct {
	AppName  string `json:"app_name"`
	IP       string `json:"ip"`
	RuleType string `json:"rule_type"` // "block" | "allow"
}

func (h *Handler) APICreateIPRule(c echo.Context) error {
	var req apiIPRuleRequest
	if err := c.Bind(&req); err != nil {
		return apiError(c, http.StatusBadRequest, "invalid JSON body")
	}
	if req.RuleType != "block" && req.RuleType != "allow" {
		return apiError(c, http.StatusBadRequest, "rule_type must be block or allow")
	}
	ip, err := normalizeIPOrCIDR(strings.TrimSpace(req.IP))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid IP or CIDR (e.g. 1.2.3.4, ::1, or 10.0.0.0/8)")
	}
	if err := h.db.AddIPRule(req.AppName, ip, req.RuleType); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusCreated, map[string]string{"app_name": req.AppName, "ip": ip, "rule_type": req.RuleType})
}

func (h *Handler) APIDeleteIPRule(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveIPRule(id); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Bans ─────────────────────────────────────────────────────────────────────
//
// There is no separate ban table: a "ban" is a global (app_name=="") block
// row in ip_rules, same as the autoban package writes (see IPRule.Auto()).
// These endpoints are a filtered, purpose-named view over the same CRUD as
// the IP-rules endpoints above, not a distinct subsystem.

// apiBanNotePrefix marks API-initiated bans. Autoban writes its own
// "Auto-banned — " prefix (autoban/autoban.go), so the IP Rules page's
// "Auto" badge logic can still tell the two sources apart.
const apiBanNotePrefix = "Banned via API — "

func (h *Handler) APIListBans(c echo.Context) error {
	rules, err := h.db.ListIPRules()
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	bans := make([]storage.IPRule, 0, len(rules))
	for _, r := range rules {
		if r.AppName == "" && r.RuleType == "block" {
			bans = append(bans, r)
		}
	}
	return c.JSON(http.StatusOK, bans)
}

type apiBanRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

func (h *Handler) APICreateBan(c echo.Context) error {
	var req apiBanRequest
	if err := c.Bind(&req); err != nil {
		return apiError(c, http.StatusBadRequest, "invalid JSON body")
	}
	ip, err := normalizeIPOrCIDR(strings.TrimSpace(req.IP))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid IP or CIDR (e.g. 1.2.3.4, ::1, or 10.0.0.0/8)")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "no reason given"
	}
	if err := h.db.AddIPRuleWithNote("", ip, "block", apiBanNotePrefix+reason); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusCreated, map[string]string{"ip": ip, "note": apiBanNotePrefix + reason})
}

// APIDeleteBan unbans by ip_rules row id. It's identical to deleting any other
// IP rule (auto-banned or manual), since that's literally what unban is
// today on the IP Rules page.
func (h *Handler) APIDeleteBan(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveIPRule(id); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.NoContent(http.StatusNoContent)
}
