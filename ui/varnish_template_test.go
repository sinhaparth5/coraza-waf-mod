package ui

import (
	"bytes"
	"strings"
	"testing"

	"coraza-waf-mod/storage"
)

// TestVarnishCardRenders executes the Settings-page Varnish card standalone
// (the same partial SaveVarnishConfig re-renders) so a renamed field or
// broken pipeline fails here instead of at first click in the UI.
func TestVarnishCardRenders(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	var buf bytes.Buffer
	err := h.tmpls["settings"].ExecuteTemplate(&buf, "varnish-card", map[string]any{
		"AdminPath":      "/admin",
		"VarnishEnabled": true,
		"VarnishAddr":    "127.0.0.1:6081",
		"VarnishSaveOK":  true,
	})
	if err != nil {
		t.Fatalf("execute varnish-card: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"127.0.0.1:6081", "/admin/settings/varnish", "Settings saved"} {
		if !strings.Contains(out, want) {
			t.Errorf("varnish-card output missing %q", want)
		}
	}
}

// TestServicesRowsRenderCacheToggle renders the services table with one
// cache-enabled and one plain service and checks the badge and per-row toggle.
func TestServicesRowsRenderCacheToggle(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	views := []ServiceView{
		{Service: storage.Service{ID: 1, Name: "cdn", Host: "cdn.example.com", Backend: "http://127.0.0.1:3000", TLSMode: "none", BotMode: "inherit", CacheEnabled: true}},
		{Service: storage.Service{ID: 2, Name: "app", Host: "app.example.com", Backend: "http://127.0.0.1:4000", TLSMode: "none", BotMode: "inherit"}},
	}
	var buf bytes.Buffer
	if err := h.tmpls["services"].ExecuteTemplate(&buf, "services-rows", views); err != nil {
		t.Fatalf("execute services-rows: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Cached") {
		t.Error("cache-enabled service row missing the Cached badge")
	}
	if !strings.Contains(out, "/admin/services/cache/1") || !strings.Contains(out, "/admin/services/cache/2") {
		t.Error("cache toggle buttons missing for one or both services")
	}
}
