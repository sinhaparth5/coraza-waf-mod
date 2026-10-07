package ui

import (
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

func TestNewStatEvent(t *testing.T) {
	ts := time.UnixMilli(1_780_000_000_000)
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
	for name, c := range map[string]struct {
		in  storage.RequestLog
		why string
	}{
		"allowed has no reason": {storage.RequestLog{Action: "proxied", RuleID: 0}, ""},
		"rule block names rule": {storage.RequestLog{Blocked: true, Action: "waf_blocked", RuleID: 942100}, "waf_blocked #942100"},
		"non-rule block":        {storage.RequestLog{Blocked: true, Action: "rate_limited"}, "rate_limited"},
	} {
		c.in.Timestamp, c.in.UserAgent = ts, ua
		got := newStatEvent(c.in)
		if got.Reason != c.why || got.T != ts.UnixMilli() || got.Browser != "Chrome" || got.OS != "Windows" {
			t.Errorf("%s: got %+v, want reason %q, t %d, Chrome/Windows", name, got, c.why, ts.UnixMilli())
		}
	}
}
