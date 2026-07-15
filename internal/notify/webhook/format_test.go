package webhook

import (
	"encoding/json"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

func sampleEntry(blocked bool, action string) storage.RequestLog {
	return storage.RequestLog{
		Timestamp: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		AppName:   "app1",
		RealIP:    "203.0.113.9",
		Method:    "GET",
		Path:      "/login",
		Status:    403,
		Blocked:   blocked,
		RuleID:    942100,
		Action:    action,
	}
}

func TestEventCategory(t *testing.T) {
	cases := []struct {
		name  string
		entry storage.RequestLog
		want  string
	}{
		{"blocked", sampleEntry(true, "waf_rule"), "blocked"},
		{"challenged", sampleEntry(false, "bot_challenge"), "challenged"},
		{"challenged adaptive", sampleEntry(false, "bot_challenge:adaptive"), "challenged"},
		{"proxied", sampleEntry(false, ""), "proxied"},
	}
	for _, tc := range cases {
		if got := eventCategory(tc.entry); got != tc.want {
			t.Errorf("%s: eventCategory = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestBuildGenericPayloadUnchanged pins the pre-existing behavior: the
// generic destination type still posts the raw RequestLog as JSON, so an
// existing SIEM/receiver integration built against it doesn't break.
func TestBuildGenericPayloadUnchanged(t *testing.T) {
	entry := sampleEntry(true, "waf_rule")
	got, err := buildPayload("generic", entry)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	want, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("generic payload = %s, want %s", got, want)
	}
}

func TestBuildSlackPayloadShape(t *testing.T) {
	entry := sampleEntry(true, "waf_rule")
	raw, err := buildPayload("slack", entry)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var decoded struct {
		Attachments []struct {
			Color  string `json:"color"`
			Blocks []struct {
				Type string `json:"type"`
				Text struct {
					Text string `json:"text"`
				} `json:"text"`
			} `json:"blocks"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("slack payload not valid JSON in expected shape: %v", err)
	}
	if len(decoded.Attachments) != 1 {
		t.Fatalf("attachments = %d, want 1", len(decoded.Attachments))
	}
	att := decoded.Attachments[0]
	if att.Color != slackColor("blocked") {
		t.Errorf("color = %q, want %q", att.Color, slackColor("blocked"))
	}
	if len(att.Blocks) == 0 || att.Blocks[0].Type != "header" {
		t.Fatalf("blocks[0] = %+v, want a header block first", att.Blocks)
	}
	if att.Blocks[0].Text.Text != "Request blocked" {
		t.Errorf("header text = %q, want %q", att.Blocks[0].Text.Text, "Request blocked")
	}
}

func TestBuildDiscordPayloadShape(t *testing.T) {
	entry := sampleEntry(false, "bot_challenge")
	raw, err := buildPayload("discord", entry)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var decoded struct {
		Embeds []struct {
			Title  string `json:"title"`
			Color  int    `json:"color"`
			Fields []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("discord payload not valid JSON in expected shape: %v", err)
	}
	if len(decoded.Embeds) != 1 {
		t.Fatalf("embeds = %d, want 1", len(decoded.Embeds))
	}
	embed := decoded.Embeds[0]
	if embed.Title != "Bot challenge issued" {
		t.Errorf("title = %q, want %q", embed.Title, "Bot challenge issued")
	}
	if embed.Color != discordColor("challenged") {
		t.Errorf("color = %d, want %d", embed.Color, discordColor("challenged"))
	}
	if len(embed.Fields) == 0 {
		t.Fatal("expected at least one field")
	}
}

func TestBuildPayloadUnknownDestinationFallsBackToGeneric(t *testing.T) {
	entry := sampleEntry(true, "waf_rule")
	got, err := buildPayload("carrier-pigeon", entry)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	want, _ := json.Marshal(entry)
	if string(got) != string(want) {
		t.Errorf("unknown destination payload = %s, want generic fallback %s", got, want)
	}
}
