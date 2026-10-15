package ui

import (
	"database/sql"
	"errors"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"palisade/internal/security/waf"
	"palisade/internal/storage"

	"github.com/labstack/echo/v4"
)

// Custom WAF rules (issue #112): SecRules stored in the DB and compiled into
// the live engines by buildWAFAll in main.go, so saving one takes effect on
// the next request with no restart or SIGHUP.

const customRuleMaxLen = 16 << 10

// checkCustomRule normalizes r and rejects it unless it compiles, uses only
// custom-range IDs no other custom rule already uses, and is scoped to an
// existing service (or globally).
func (h *Handler) checkCustomRule(r *storage.WAFCustomRule) error {
	r.Rule = strings.TrimSpace(r.Rule)
	r.ServiceName = strings.TrimSpace(r.ServiceName)
	r.Note = strings.TrimSpace(r.Note)
	if r.Rule == "" {
		return errors.New("enter a rule")
	}
	if len(r.Rule) > customRuleMaxLen {
		return fmt.Errorf("a rule can be at most %d bytes", customRuleMaxLen)
	}
	if r.ServiceName != "" {
		if !slices.ContainsFunc(h.registry.List(), func(s storage.Service) bool { return s.Name == r.ServiceName }) {
			return fmt.Errorf("no service named %q", r.ServiceName)
		}
	}
	ids, err := waf.ValidateCustomRule(r.Rule)
	if err != nil {
		return err
	}
	others, err := h.db.ListWAFCustomRules()
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.ID == r.ID {
			continue
		}
		for _, id := range waf.CustomRuleIDs(o.Rule) {
			if slices.Contains(ids, id) {
				return fmt.Errorf("rule id %d is already used by custom rule #%d", id, o.ID)
			}
		}
	}
	return nil
}

func (h *Handler) renderWAFContent(c echo.Context) error {
	data, err := h.wafRulesContentData()
	if err != nil {
		return err
	}
	return h.renderPartial(c, "waf_rules", "waf-content", data)
}

// SaveCustomRule handles POST /admin/waf-rules/custom: adds a rule, or
// updates one when the form carries its id.
func (h *Handler) SaveCustomRule(c echo.Context) error {
	r := storage.WAFCustomRule{Rule: c.FormValue("rules"), ServiceName: c.FormValue("service"), Note: c.FormValue("note"), Enabled: true}
	if v := c.FormValue("id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid id")
		}
		r.ID = id
	}
	if err := h.checkCustomRule(&r); err != nil {
		c.Response().Header().Set("HX-Retarget", "#custom-rule-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(err.Error()))
	}
	if err := h.db.SaveWAFCustomRule(r); err != nil {
		return err
	}
	h.reloadWAF()
	c.Response().Header().Set("HX-Trigger", "custom-rule-saved")
	return h.renderWAFContent(c)
}

// ToggleCustomRule handles POST /admin/waf-rules/custom/:id/toggle.
func (h *Handler) ToggleCustomRule(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.SetWAFCustomRuleEnabled(id, c.FormValue("enabled") == "1"); err != nil {
		return err
	}
	h.reloadWAF()
	return h.renderWAFContent(c)
}

// DeleteCustomRule handles DELETE /admin/waf-rules/custom/:id.
func (h *Handler) DeleteCustomRule(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.DeleteWAFCustomRule(id); err != nil {
		return err
	}
	h.reloadWAF()
	return h.renderWAFContent(c)
}

// ── REST API ─────────────────────────────────────────────────────────────────

type apiCustomRuleRequest struct {
	ServiceName string `json:"service_name"`
	Rule        string `json:"rule"`
	Note        string `json:"note"`
	Enabled     *bool  `json:"enabled"` // default true
}

func (h *Handler) APIListCustomRules(c echo.Context) error {
	rules, err := h.db.ListWAFCustomRules()
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, rules)
}

// apiSaveCustomRule backs both POST (id 0) and PUT /waf-rules/custom/:id.
func (h *Handler) apiSaveCustomRule(c echo.Context, id int64) error {
	var req apiCustomRuleRequest
	if err := c.Bind(&req); err != nil {
		return apiError(c, http.StatusBadRequest, "invalid JSON body")
	}
	r := storage.WAFCustomRule{ID: id, ServiceName: req.ServiceName, Rule: req.Rule, Note: req.Note, Enabled: req.Enabled == nil || *req.Enabled}
	if err := h.checkCustomRule(&r); err != nil {
		return apiError(c, http.StatusBadRequest, err.Error())
	}
	if err := h.db.SaveWAFCustomRule(r); errors.Is(err, sql.ErrNoRows) {
		return apiError(c, http.StatusNotFound, "custom rule not found")
	} else if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if id != 0 && req.Enabled != nil {
		if err := h.db.SetWAFCustomRuleEnabled(id, *req.Enabled); err != nil {
			return apiError(c, http.StatusInternalServerError, err.Error())
		}
	}
	h.reloadWAF()
	// Custom rule IDs are unique across rows (checkCustomRule), so the
	// rule's first SecRule id finds the saved row, new id included.
	first := waf.CustomRuleIDs(r.Rule)[0]
	rules, err := h.db.ListWAFCustomRules()
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	status := http.StatusOK
	if id == 0 {
		status = http.StatusCreated
	}
	for _, o := range rules {
		if waf.CustomRuleIDs(o.Rule)[0] == first {
			return c.JSON(status, o)
		}
	}
	return c.NoContent(status)
}

func (h *Handler) APICreateCustomRule(c echo.Context) error { return h.apiSaveCustomRule(c, 0) }

func (h *Handler) APIUpdateCustomRule(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	return h.apiSaveCustomRule(c, id)
}

func (h *Handler) APIDeleteCustomRule(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	if err := h.db.DeleteWAFCustomRule(id); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	h.reloadWAF()
	return c.NoContent(http.StatusNoContent)
}
