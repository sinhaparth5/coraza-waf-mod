package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

// TestAPIKeysCardRenders executes the Settings-page API Keys card standalone
// (the same partial CreateAPIKey/DeleteAPIKey re-render) so a renamed field
// or broken pipeline fails here instead of at first click in the UI. Checks
// both states: a freshly generated key shown once, and the save-error path.
func TestAPIKeysCardRenders(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	now := time.Now()
	keys := []storage.APIKey{
		{ID: 1, Name: "ci-deploy", Prefix: "cwaf_abcd1234", CreatedAt: now, LastUsedAt: &now},
		{ID: 2, Name: "terraform", Prefix: "cwaf_ef567890", CreatedAt: now, LastUsedAt: nil},
	}

	var buf bytes.Buffer
	err := h.tmpls["settings"].ExecuteTemplate(&buf, "api-keys-card", map[string]any{
		"AdminPath": "/admin",
		"APIKeys":   keys,
		"NewAPIKey": "cwaf_full_secret_value_shown_once",
	})
	if err != nil {
		t.Fatalf("execute api-keys-card: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"/admin/settings/api-keys", "/admin/api/v1",
		"cwaf_full_secret_value_shown_once", "won't be shown again",
		"ci-deploy", "cwaf_abcd1234", "terraform", "cwaf_ef567890", "Never",
		`data-copy-value="cwaf_full_secret_value_shown_once"`, "copy-btn-icon", "copy-btn-label",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("api-keys-card output missing %q", want)
		}
	}
	// The raw secret appears exactly twice by design — the visible <code> and
	// the copy button's data-copy-value — and never a third time; a third
	// occurrence would mean it leaked somewhere else in a later re-render.
	if n := strings.Count(out, "cwaf_full_secret_value_shown_once"); n != 2 {
		t.Errorf("raw key must appear exactly twice (display + copy button), got %d occurrences", n)
	}

	buf.Reset()
	err = h.tmpls["settings"].ExecuteTemplate(&buf, "api-keys-card", map[string]any{
		"AdminPath":     "/admin",
		"APIKeys":       []storage.APIKey{},
		"APIKeySaveErr": "Name is required.",
	})
	if err != nil {
		t.Fatalf("execute api-keys-card with save error: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "Name is required.") {
		t.Errorf("api-keys-card save-error output missing the error message")
	}
	if strings.Contains(out, "cwaf_full_secret_value_shown_once") {
		t.Errorf("api-keys-card must not carry over a raw key from a prior render")
	}
}

// TestAPIKeysRowsRevokeURL checks the standalone rows partial DeleteAPIKey
// re-renders — it's invoked with a plain {AdminPath, Keys} map rather than
// the full settings-page data, so a "$.AdminPath" scoping mistake inside a
// {{range}} would silently produce an empty/broken revoke URL instead of a
// template error.
func TestAPIKeysRowsRevokeURL(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	keys := []storage.APIKey{{ID: 7, Name: "ci-deploy", Prefix: "cwaf_abcd1234", CreatedAt: time.Now()}}
	var buf bytes.Buffer
	err := h.tmpls["settings"].ExecuteTemplate(&buf, "api-keys-rows", map[string]any{
		"AdminPath": "/admin",
		"Keys":      keys,
	})
	if err != nil {
		t.Fatalf("execute api-keys-rows: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "/admin/settings/api-keys/7") {
		t.Errorf("api-keys-rows missing revoke URL for key 7, got:\n%s", out)
	}

	buf.Reset()
	if err := h.tmpls["settings"].ExecuteTemplate(&buf, "api-keys-rows", map[string]any{
		"AdminPath": "/admin",
		"Keys":      []storage.APIKey{},
	}); err != nil {
		t.Fatalf("execute api-keys-rows (empty): %v", err)
	}
	if !strings.Contains(buf.String(), "No API keys yet") {
		t.Errorf("api-keys-rows empty state missing, got:\n%s", buf.String())
	}
}
