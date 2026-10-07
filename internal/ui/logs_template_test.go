package ui

import (
	"bytes"
	"strings"
	"testing"

	"coraza-waf-mod/internal/storage"
)

// TestLogsPageLiveViewHasStatsToggle renders the live (non-history) Logs
// page and checks the Table/Stats toggle and the Stats view skeleton that
// logs.js fills in.
func TestLogsPageLiveViewHasStatsToggle(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Page":       "logs",
		"Heading":    "Live Logs",
		"AdminPath":  "/waf-admin",
		"AlertCount": 0,
		"Apps":       []any{},
		"History":    false,
		"Recent":     []storage.LogRow{},
		"Total":      0,
		"CurPage":    1,
		"TotalPages": 1,
	}

	var buf bytes.Buffer
	if err := h.tmpls["logs"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute logs template: %v", err)
	}
	page := buf.String()

	for _, want := range []string{
		`id="view-table-btn"`, `id="view-stats-btn"`, `id="log-card"`, `id="stats-view"`,
		`id="st-since"`, `id="st-timeline"`,
		// every panel logs.js renders into (st.maps keys)
		`id="st-path"`, `id="st-ip"`, `id="st-why"`, `id="st-nf"`, `id="st-status"`,
		`id="st-cc"`, `id="st-app"`, `id="st-br"`, `id="st-os"`,
		`id="log-columns"`, `id="table-format-hint"`,
		`id="new-rows-pill"`, `id="live-text"`, `id="logs-notice"`,
		`action="/waf-admin/logs"`, // honours a custom admin path, not a hardcoded /admin
		`/waf-admin/static/js/pickers.min.js`, `/waf-admin/static/js/logstats.min.js`, `/waf-admin/static/js/logs.min.js`,
		`id="ld-threat-section"`, `id="ld-threat-score"`, `id="ld-threat-breakdown"`, // unified threat score (issue #12)
	} {
		if !strings.Contains(page, want) {
			t.Errorf("live logs page missing %q", want)
		}
	}
	if n := strings.Count(page, `class="st-tile`); n != 6 {
		t.Errorf("got %d overview tiles, want 6 (logs.js fills them by position)", n)
	}
}

// TestLogsPageHistoryViewHasNoStatsToggle checks the filtered/paginated
// history view (which has no live stream at all) never renders the
// table/stats toggle or the Stats view; both need the live SSE connection.
func TestLogsPageHistoryViewHasNoStatsToggle(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Page":       "logs",
		"Heading":    "Live Logs",
		"AdminPath":  "/admin",
		"AlertCount": 0,
		"Apps":       []any{},
		"History":    true,
		"Recent":     []storage.LogRow{},
		"Total":      0,
		"CurPage":    1,
		"TotalPages": 1,
	}

	var buf bytes.Buffer
	if err := h.tmpls["logs"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute logs template (history): %v", err)
	}
	page := buf.String()

	for _, dontWant := range []string{`id="view-table-btn"`, `id="stats-view"`} {
		if strings.Contains(page, dontWant) {
			t.Errorf("history logs page must not render %q (no live stream to switch)", dontWant)
		}
	}
}
