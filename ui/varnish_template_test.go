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

// TestServicesRowsAreLabelsPlusEdit renders the services table and checks the
// row layout contract: status badges only, one Edit button per row carrying
// every data attribute the edit modal populates itself from, and none of the
// old per-row manage/toggle controls.
func TestServicesRowsAreLabelsPlusEdit(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	views := []ServiceView{
		{Service: storage.Service{ID: 1, Name: "cdn", Host: "cdn.example.com", Backend: "http://127.0.0.1:3000", TLSMode: "none", BotMode: "always", RateLimitRPS: 10, RateLimitBurst: 20, CacheEnabled: true}},
		{Service: storage.Service{ID: 2, Name: "app", Prefix: "/api", Backend: "http://127.0.0.1:4000", TLSMode: "none", BotMode: "inherit"}},
	}
	var buf bytes.Buffer
	if err := h.tmpls["services"].ExecuteTemplate(&buf, "services-rows", views); err != nil {
		t.Fatalf("execute services-rows: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"Cached", "10/s", "Bot: always", "svc-edit-btn",
		`data-id="1"`, `data-has-host="1"`, `data-rps="10"`, `data-burst="20"`, `data-mode="always"`, `data-cache="1"`,
		`data-id="2"`, `data-has-host="0"`, `data-cache="0"`} {
		if !strings.Contains(out, want) {
			t.Errorf("services-rows output missing %q", want)
		}
	}
	for _, gone := range []string{"tls-manage-btn", "rl-manage-btn", "bot-manage-btn", "/admin/services/cache/"} {
		if strings.Contains(out, gone) {
			t.Errorf("services-rows still contains removed per-row control %q", gone)
		}
	}
}

// TestServicesPageRendersEditModal executes the full services page and checks
// the unified edit modal is present with all four setting tabs, their forms,
// and the danger-zone delete button.
func TestServicesPageRendersEditModal(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Page":       "services",
		"Heading":    "Services",
		"AdminPath":  "/admin",
		"AlertCount": 0,
		"Services":   []ServiceView{},
		"PoolCerts":  nil,
	}
	var buf bytes.Buffer
	if err := h.tmpls["services"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute services template: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"svc-modal-overlay", "svc-tabs",
		`data-tab="ratelimit"`, `data-tab="bot"`, `data-tab="cache"`, `data-tab="tls"`,
		"rl-form", "bot-form", "svc-cache-form", "tls-pool-form", "tls-upload-form", "tls-auto-form", "tls-clear-form",
		"svc-delete-btn",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("services page missing edit-modal element %q", want)
		}
	}
}

// TestRateLimitCardRenders executes the Settings-page rate-limit card with
// the global limiter fields so a renamed field or broken form wiring fails
// here instead of at first click in the UI.
func TestRateLimitCardRenders(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	var buf bytes.Buffer
	err := h.tmpls["settings"].ExecuteTemplate(&buf, "ratelimit-card", map[string]any{
		"AdminPath":   "/admin",
		"RLBackend":   "memory",
		"RLRedisAddr": "",
		"RLEnabled":   true,
		"RLRPS":       2.5,
		"RLBurst":     40,
		"RLSaveOK":    true,
	})
	if err != nil {
		t.Fatalf("execute ratelimit-card: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"/admin/settings/ratelimit",
		`name="rl_enabled"`, `name="rl_rps"`, `name="rl_burst"`,
		`value="2.5"`, `value="40"`, "Settings saved",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ratelimit-card output missing %q", want)
		}
	}
}
