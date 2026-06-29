package ui

import (
	"bytes"
	"testing"

	"coraza-waf-mod/storage"
)

func TestDashboardTemplateRendersAtAGlanceCards(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Page":          "dashboard",
		"Heading":       "Dashboard",
		"AdminPath":     "/admin",
		"AlertCount":    0,
		"Stats":         storage.Stats{},
		"Recent":        []storage.LogRow{},
		"TopBlocked":    []storage.LogRow{},
		"TopCountries":  []dashboardCountry{},
		"AtAGlance":     dashboardAtAGlance(storage.AtAGlanceStats{RequestsLastMinute: 12}, 2),
		"BlockRate":     0,
		"HasTraffic":    false,
		"TrackArc":      310,
		"AllowedArc":    0,
		"BlockedArc":    0,
		"BlockedOffset": 0,
		"Apps":          []any{"app-a", "app-b"},
		"BotStats":      storage.BotStats{},
	}

	var buf bytes.Buffer
	if err := h.tmpls["dashboard"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute dashboard template: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Requests/sec")) {
		t.Fatal("dashboard did not render at-a-glance cards")
	}
}
