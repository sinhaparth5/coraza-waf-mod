package storage

import (
	"testing"
	"time"
)

// TestGetDailyReport exercises the aggregate query against the real driver —
// in particular COUNT(DISTINCT ...) FILTER, which not every SQLite build
// supports — and the plain time-comparison window bounds.
func TestGetDailyReport(t *testing.T) {
	db := openTestDB(t)

	day := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	insert := func(offset time.Duration, ip string, status int, blocked bool, ruleID int, action string) {
		t.Helper()
		if _, err := db.InsertRequest(RequestLog{
			Timestamp: day.Add(offset), AppName: "app", RealIP: ip,
			Method: "GET", Host: "h", Path: "/", Status: status,
			Blocked: blocked, RuleID: ruleID, Action: action,
		}); err != nil {
			t.Fatal(err)
		}
	}

	insert(1*time.Hour, "1.1.1.1", 200, false, 0, "")                       // clean
	insert(2*time.Hour, "2.2.2.2", 403, true, 941100, "deny")               // WAF block
	insert(3*time.Hour, "2.2.2.2", 403, true, 0, "ip_blocked")              // same IP, blocklist
	insert(4*time.Hour, "3.3.3.3", 403, true, 0, "geo_blocked:CN")          // geo
	insert(5*time.Hour, "4.4.4.4", 429, true, 0, "rate_limited")            // rate limit
	insert(6*time.Hour, "5.5.5.5", 302, false, 0, "bot_challenge")          // challenge
	insert(-1*time.Hour, "6.6.6.6", 403, true, 0, "ip_blocked")             // before window
	insert(24*time.Hour+time.Minute, "7.7.7.7", 403, true, 0, "ip_blocked") // after window

	rep, err := db.GetDailyReport(day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("GetDailyReport: %v", err)
	}

	want := DailyReport{
		Total: 6, Blocked: 4, Status403: 3, UniqueBlockedIPs: 3,
		WAFBlocked: 1, IPBlocked: 1, GeoBlocked: 1, RateLimited: 1, BotChallenged: 1,
	}
	if rep != want {
		t.Errorf("GetDailyReport = %+v, want %+v", rep, want)
	}
}
