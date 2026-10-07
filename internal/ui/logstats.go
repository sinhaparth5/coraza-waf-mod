package ui

import (
	"net/http"
	"strconv"
	"time"

	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

// The Logs page Stats view is a GoAccess-style live summary. The browser does
// the counting: it loads the last hour once from LogStatsSeed, then adds each
// "stat" event that LogsStream sends next to the table row, so the stats move
// as fast as the table does and keep counting while the Table tab is open.
const (
	statsSeedWindow = time.Hour
	statsSeedLimit  = 5000
)

// statEvent is one request, reduced to the fields the Stats view counts.
// Short JSON keys because every live request sends one.
type statEvent struct {
	ID      int    `json:"id"`
	T       int64  `json:"t"` // unix ms
	App     string `json:"app"`
	IP      string `json:"ip"`
	Country string `json:"cc"`
	Method  string `json:"m"`
	Path    string `json:"p"`
	Status  int    `json:"s"`
	Blocked bool   `json:"blk"`
	Reason  string `json:"why,omitempty"` // action, plus the rule ID when a rule fired
	Ms      int64  `json:"ms"`
	Browser string `json:"br"`
	OS      string `json:"os"`
}

func newStatEvent(e storage.RequestLog) statEvent {
	browser, os := uaBrowserOS(e.UserAgent)
	reason := ""
	if e.Blocked {
		reason = e.Action
		if e.RuleID > 0 {
			reason += " #" + strconv.Itoa(e.RuleID)
		}
	}
	return statEvent{
		ID: e.ID, T: e.Timestamp.UnixMilli(), App: e.AppName, IP: e.RealIP, Country: e.Country,
		Method: e.Method, Path: e.Path, Status: e.Status, Blocked: e.Blocked, Reason: reason,
		Ms: e.Duration, Browser: browser, OS: os,
	}
}

// LogStatsSeed handles GET /admin/logs/stats: the last hour of requests
// (capped at statsSeedLimit, newest kept) for the Stats view to start from.
func (h *Handler) LogStatsSeed(c echo.Context) error {
	since := time.Now().Add(-statsSeedWindow)
	rows, err := h.db.ListRecentRequestLogs(since, statsSeedLimit)
	if err != nil {
		return err
	}
	events := make([]statEvent, len(rows))
	for i, r := range rows {
		events[i] = newStatEvent(r)
	}
	if len(rows) == statsSeedLimit {
		since = rows[0].Timestamp // capped: the data starts later than an hour ago
	}
	return c.JSON(http.StatusOK, map[string]any{"since": since.UnixMilli(), "events": events})
}
