package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/storage"
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
}
