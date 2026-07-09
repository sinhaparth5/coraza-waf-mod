package ui

import (
	"bytes"
	"strings"
	"testing"

	"coraza-waf-mod/internal/storage"
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

// TestBaseTemplateCarriesCSRF renders a full page and checks the CSRF token
// lands where the clients pick it up: hx-headers on <body> (HTMX requests),
// data-csrf (fetch calls in app.js), and the logout form's hidden input.
func TestBaseTemplateCarriesCSRF(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	token := csrfToken("some-session")
	data := map[string]any{
		"Page":       "settings",
		"Heading":    "Settings",
		"AdminPath":  "/admin",
		"AlertCount": 0,
		"CSRF":       token,
		// Minimal card data mirroring SettingsPage's defaults.
		"AdminEmail":     "admin@example.com",
		"BotEnabled":     false,
		"BotThreshold":   5,
		"BotTTL":         3600,
		"RLBackend":      "memory",
		"RLRedisAddr":    "",
		"WebhookURL":     "",
		"WebhookSecret":  "",
		"WebhookEnabled": false,
		"WebhookEvents":  "",
		"EmailEnabled":   false,
		"EmailSender":    "alert@example.com",
		"EmailTo":        "",
		"EmailTokenSet":  false,
	}

	var buf bytes.Buffer
	if err := h.tmpls["settings"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute settings template: %v", err)
	}
	page := buf.String()

	// The JSON quotes are template literals (not interpolated), so
	// html/template leaves them intact inside the single-quoted attribute
	// and HTMX can JSON-parse the value directly.
	wantHeaders := `hx-headers='{"X-CSRF-Token":"` + token + `"}'`
	for _, want := range []string{
		wantHeaders,
		`data-csrf="` + token + `"`,
		`name="_csrf" value="` + token + `"`,
		`action="/admin/settings/backup" method="POST"`, // backup must not be a GET link
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	if strings.Contains(page, `href="/admin/settings/backup"`) {
		t.Error("backup is still reachable as a GET link")
	}
}
