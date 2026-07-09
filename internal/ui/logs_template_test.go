package ui

import (
	"bytes"
	"strings"
	"testing"

	"coraza-waf-mod/internal/storage"
)

// TestLogsPageLiveViewHasTerminalToggle renders the live (non-history) Logs
// page and checks the Table/Terminal toggle and the dark access-log panel
// are present, with white-on-black styling and no "nginx-style" wording.
func TestLogsPageLiveViewHasTerminalToggle(t *testing.T) {
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
		`id="view-table-btn"`, `id="view-terminal-btn"`,
		`id="access-log-wrapper"`, `id="access-log-feed"`, `id="access-log-empty"`,
		`id="log-columns"`, `id="table-format-hint"`,
		"bg-slate-900", "text-white",
		"overflow-auto", "whitespace-pre", // no wrap + horizontal scroll, not soft-wrapped
		`id="ld-threat-section"`, `id="ld-threat-score"`, `id="ld-threat-breakdown"`, // unified threat score (issue #12)
	} {
		if !strings.Contains(page, want) {
			t.Errorf("live logs page missing %q", want)
		}
	}
	if strings.Contains(page, "nginx-style") {
		t.Error(`live logs page must not mention "nginx-style"`)
	}
	if strings.Contains(page, "text-green-400") {
		t.Error("access log panel must use white text, not green — text-green-400 still present")
	}
	// The old combined class ("whitespace-pre-wrap break-all", soft-wrapping)
	// was unique to the access-log-feed div — break-all alone is legitimately
	// reused elsewhere on this page (the log-detail modal's User-Agent,
	// Request ID, etc.), so only the exact old combo is checked, not either
	// class in isolation.
	if strings.Contains(page, "whitespace-pre-wrap break-all") {
		t.Error("access log panel must not soft-wrap lines (whitespace-pre-wrap break-all) — horizontal scroll instead")
	}
}

// TestLogsPageAccessLogRecentPreload checks the access-log terminal panel
// renders preloaded history lines (so it doesn't start empty on every page
// load) and that the empty-state placeholder is suppressed once there's
// real content.
func TestLogsPageAccessLogRecentPreload(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Page":            "logs",
		"Heading":         "Live Logs",
		"AdminPath":       "/admin",
		"AlertCount":      0,
		"Apps":            []any{},
		"History":         false,
		"Recent":          []storage.LogRow{},
		"AccessLogRecent": []string{`203.0.113.7 - - [09/Jul/2026:14:32:10 +0100] "GET /api/foo HTTP/1.1" 200 - "-" "test-agent"`},
		"Total":           0,
		"CurPage":         1,
		"TotalPages":      1,
	}

	var buf bytes.Buffer
	if err := h.tmpls["logs"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute logs template: %v", err)
	}
	page := buf.String()

	if !strings.Contains(page, "GET /api/foo HTTP/1.1") {
		t.Error("preloaded access-log line did not render")
	}
	if strings.Contains(page, `id="access-log-empty"`) {
		t.Error("empty-state placeholder must not render when AccessLogRecent has entries")
	}
}

// TestLogsPageHistoryViewHasNoTerminalToggle checks the filtered/paginated
// history view (which has no live stream at all) never renders the
// table/terminal toggle or the access-log panel — those only make sense
// alongside a live SSE connection.
func TestLogsPageHistoryViewHasNoTerminalToggle(t *testing.T) {
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

	for _, dontWant := range []string{`id="view-table-btn"`, `id="access-log-wrapper"`} {
		if strings.Contains(page, dontWant) {
			t.Errorf("history logs page must not render %q (no live stream to switch)", dontWant)
		}
	}
}
