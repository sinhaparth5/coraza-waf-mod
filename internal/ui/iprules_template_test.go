package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

// TestIPRulesTemplateRendersAutobanAndNotes renders the IP Rules page with an
// auto-banned rule and checks the autoban settings card and the Auto badge +
// ban-reason note both land in the output.
func TestIPRulesTemplateRendersAutobanAndNotes(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	rules := []storage.IPRule{
		{ID: 1, IP: "203.0.113.7", RuleType: "block",
			Note:      "Auto-banned — 12 blocked requests in 10 min (2 critical WAF hits)",
			CreatedAt: time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)},
		{ID: 2, IP: "1.2.3.4", RuleType: "allow", CreatedAt: time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)},
	}
	data := map[string]any{
		"Page":           "ip_rules",
		"Heading":        "IP Rules",
		"AdminPath":      "/admin",
		"AlertCount":     0,
		"Rules":          rules,
		"CurPage":        1,
		"TotalPages":     1,
		"Total":          2,
		"Apps":           []any{},
		"BlockCount":     1,
		"AllowCount":     1,
		"BlockPct":       50,
		"AllowPct":       50,
		"AutobanEnabled": true,
		"AutobanThresh":  10,
		"AutobanWindow":  10,
	}

	var buf bytes.Buffer
	if err := h.tmpls["ip_rules"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute ip_rules template: %v", err)
	}
	page := buf.String()

	for _, want := range []string{
		"Automatic banning",
		`hx-post="/admin/ip-rules/autoban"`,
		`name="autoban_threshold"`,
		`bg-amber-100 text-amber-700">Auto</span>`, // badge on the auto-banned row
		"Auto-banned — 12 blocked requests in 10 min",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	// The manual rule must not carry the Auto badge: exactly one occurrence.
	if got := strings.Count(page, `bg-amber-100 text-amber-700">Auto</span>`); got != 1 {
		t.Errorf("Auto badge count = %d, want 1", got)
	}
	// The card-header badge must show the true total row count, not just how
	// many rows are on the current page (they're equal here, single page —
	// TestIPRulesRowsPagination below checks the case where they diverge).
	if !strings.Contains(page, "2 rules") {
		t.Error(`card-header badge missing "2 rules" (must use .Total, not len(.Rules))`)
	}
	// Single page: no Prev/Next controls should render at all.
	if strings.Contains(page, "Page 1 of 1") {
		t.Error("pagination footer must not render when there's only one page")
	}
}

// TestIPRulesRowsPagination renders the ip-rules-rows partial directly (the
// same one AddIPRule/DeleteIPRule/IPRulesRows re-render) across a few page
// positions and checks the Prev/Next controls, the revoke URL's ?page=
// carry-through, and the total-count text — the parts a "CurPage" vs "Page"
// key mixup (h.render overwrites "Page" with the template name) would break.
func TestIPRulesRowsPagination(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	rules := []storage.IPRule{{ID: 42, IP: "203.0.113.7", RuleType: "block", CreatedAt: time.Now()}}

	render := func(curPage, totalPages, total int) string {
		var buf bytes.Buffer
		err := h.tmpls["ip_rules"].ExecuteTemplate(&buf, "ip-rules-rows", map[string]any{
			"AdminPath": "/admin", "Rules": rules,
			"CurPage": curPage, "TotalPages": totalPages, "Total": total,
		})
		if err != nil {
			t.Fatalf("execute ip-rules-rows (page %d/%d): %v", curPage, totalPages, err)
		}
		return buf.String()
	}

	// Middle page: both Prev and Next enabled, and the delete URL carries the
	// current page so deleting doesn't bounce the admin back to page 1.
	out := render(2, 3, 120)
	if !strings.Contains(out, "/admin/ip-rules/42?page=2") {
		t.Errorf("remove-btn URL missing ?page=2 carry-through, got:\n%s", out)
	}
	if !strings.Contains(out, "Page 2 of 3 · 120 rules") {
		t.Errorf("pagination label wrong, got:\n%s", out)
	}
	if !strings.Contains(out, `hx-get="/admin/ip-rules/rows?page=1"`) {
		t.Error("Prev button must hx-get page 1")
	}
	if !strings.Contains(out, `hx-get="/admin/ip-rules/rows?page=3"`) {
		t.Error("Next button must hx-get page 3")
	}
	if strings.Contains(out, "disabled") {
		t.Error("middle page must not disable either Prev or Next")
	}

	// First page: Prev disabled.
	out = render(1, 3, 120)
	if !strings.Contains(out, "Prev</button>") || !strings.Contains(out, "disabled") {
		t.Errorf("first page must render a disabled Prev button, got:\n%s", out)
	}
	if strings.Contains(out, `hx-get="/admin/ip-rules/rows?page=0"`) {
		t.Error("first page must not offer a Prev link to page 0")
	}

	// Last page: Next disabled.
	out = render(3, 3, 120)
	if !strings.Contains(out, `hx-get="/admin/ip-rules/rows?page=2"`) {
		t.Error("last page must still offer a Prev link to page 2")
	}
	if strings.Contains(out, `hx-get="/admin/ip-rules/rows?page=4"`) {
		t.Error("last page must not offer a Next link past the end")
	}
}
