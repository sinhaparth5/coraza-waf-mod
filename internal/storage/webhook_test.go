package storage

import (
	"testing"
)

func TestWebhookConfigDefaultsToGenericDestination(t *testing.T) {
	db := openTestDB(t)

	cfg, err := db.GetWebhookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DestinationType != "generic" {
		t.Errorf("default DestinationType = %q, want %q", cfg.DestinationType, "generic")
	}
}

func TestWebhookConfigRoundTripsDestinationType(t *testing.T) {
	db := openTestDB(t)

	for _, dt := range []string{"generic", "slack", "discord"} {
		if err := db.SetWebhookConfig(WebhookConfig{URL: "https://hooks.example.com/x", Enabled: true, Events: "blocked", DestinationType: dt}); err != nil {
			t.Fatalf("SetWebhookConfig(%s): %v", dt, err)
		}
		got, err := db.GetWebhookConfig()
		if err != nil {
			t.Fatal(err)
		}
		if got.DestinationType != dt {
			t.Errorf("round-tripped DestinationType = %q, want %q", got.DestinationType, dt)
		}
	}
}

// TestWebhookConfigNormalizesUnknownDestinationType covers a value that
// might arrive from a rolled-back future version or a hand-edited DB row:
// it must never be persisted verbatim, since the webhook package's
// buildPayload only recognizes "slack"/"discord" and otherwise silently
// falls back to generic — better to make that fallback visible in the
// stored config too.
func TestWebhookConfigNormalizesUnknownDestinationType(t *testing.T) {
	db := openTestDB(t)

	if err := db.SetWebhookConfig(WebhookConfig{URL: "https://x", DestinationType: "carrier-pigeon"}); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetWebhookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.DestinationType != "generic" {
		t.Errorf("unknown DestinationType normalized to %q, want %q", got.DestinationType, "generic")
	}
}
