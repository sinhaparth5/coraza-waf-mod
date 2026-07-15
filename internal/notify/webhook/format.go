package webhook

import (
	"encoding/json"
	"fmt"
	"strings"

	"coraza-waf-mod/internal/storage"
)

// eventCategory classifies entry the same way shouldSend filters on it:
// "blocked", "challenged" (prefix match — issue #16's adaptive enforcement
// also logs as "bot_challenge:adaptive"), or "proxied" otherwise. Shared by
// the event filter and the Slack/Discord formatters so the two never
// classify the same entry differently.
func eventCategory(entry storage.RequestLog) string {
	if entry.Blocked {
		return "blocked"
	}
	if strings.HasPrefix(entry.Action, "bot_challenge") {
		return "challenged"
	}
	return "proxied"
}

// categoryTitle and categoryColor give each category a consistent label and
// accent color across the Slack and Discord formatters.
func categoryTitle(category string) string {
	switch category {
	case "blocked":
		return "Request blocked"
	case "challenged":
		return "Bot challenge issued"
	default:
		return "Request proxied"
	}
}

// slackColor / discordColor are the same three-color severity scheme
// (red = blocked, amber = challenged, green = proxied/test) expressed in
// each platform's expected format: Slack attachments take a hex string,
// Discord embeds take a decimal integer.
func slackColor(category string) string {
	switch category {
	case "blocked":
		return "#dc2626"
	case "challenged":
		return "#d97706"
	default:
		return "#16a34a"
	}
}

func discordColor(category string) int {
	switch category {
	case "blocked":
		return 0xdc2626
	case "challenged":
		return 0xd97706
	default:
		return 0x16a34a
	}
}

// buildGenericPayload preserves the pre-existing behavior: the raw
// RequestLog as JSON, for a custom receiver or SIEM ingest endpoint.
func buildGenericPayload(entry storage.RequestLog) ([]byte, error) {
	return json.Marshal(entry)
}

// buildSlackPayload formats entry as a Slack Block Kit message wrapped in a
// single colored attachment (attachments still support a color bar; plain
// top-level blocks don't), so a block/challenge/test alert is visually
// distinguishable in a channel at a glance.
func buildSlackPayload(entry storage.RequestLog) ([]byte, error) {
	category := eventCategory(entry)
	fields := []map[string]any{
		{"type": "mrkdwn", "text": fmt.Sprintf("*IP*\n%s", orDash(entry.RealIP))},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Path*\n%s %s", orDash(entry.Method), orDash(entry.Path))},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Status*\n%d", entry.Status)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Action*\n%s", orDash(entry.Action))},
	}
	if entry.AppName != "" {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Service*\n%s", entry.AppName)})
	}
	if entry.RuleID != 0 {
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*Rule*\n%d", entry.RuleID)})
	}

	payload := map[string]any{
		"attachments": []map[string]any{
			{
				"color": slackColor(category),
				"blocks": []map[string]any{
					{
						"type": "header",
						"text": map[string]any{"type": "plain_text", "text": categoryTitle(category), "emoji": true},
					},
					{
						"type":   "section",
						"fields": fields,
					},
					{
						"type": "context",
						"elements": []map[string]any{
							{"type": "mrkdwn", "text": fmt.Sprintf("Coraza WAF Mod · %s", entry.Timestamp.Format("2006-01-02 15:04:05 MST"))},
						},
					},
				},
			},
		},
	}
	return json.Marshal(payload)
}

// buildDiscordPayload formats entry as a Discord webhook message carrying a
// single embed, using Discord's field-array embed shape.
func buildDiscordPayload(entry storage.RequestLog) ([]byte, error) {
	category := eventCategory(entry)
	fields := []map[string]any{
		{"name": "IP", "value": orDash(entry.RealIP), "inline": true},
		{"name": "Path", "value": fmt.Sprintf("%s %s", orDash(entry.Method), orDash(entry.Path)), "inline": true},
		{"name": "Status", "value": fmt.Sprintf("%d", entry.Status), "inline": true},
		{"name": "Action", "value": orDash(entry.Action), "inline": true},
	}
	if entry.AppName != "" {
		fields = append(fields, map[string]any{"name": "Service", "value": entry.AppName, "inline": true})
	}
	if entry.RuleID != 0 {
		fields = append(fields, map[string]any{"name": "Rule", "value": fmt.Sprintf("%d", entry.RuleID), "inline": true})
	}

	payload := map[string]any{
		"embeds": []map[string]any{
			{
				"title":     categoryTitle(category),
				"color":     discordColor(category),
				"fields":    fields,
				"footer":    map[string]any{"text": "Coraza WAF Mod"},
				"timestamp": entry.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			},
		},
	}
	return json.Marshal(payload)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// buildPayload chooses the payload builder for cfg's configured destination
// type. Unknown/empty destination types (should already be normalized by
// storage.DB.GetWebhookConfig, but a defensive default here costs nothing)
// fall back to the original generic JSON body.
func buildPayload(destinationType string, entry storage.RequestLog) ([]byte, error) {
	switch destinationType {
	case "slack":
		return buildSlackPayload(entry)
	case "discord":
		return buildDiscordPayload(entry)
	default:
		return buildGenericPayload(entry)
	}
}
