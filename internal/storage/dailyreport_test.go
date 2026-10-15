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

func TestGetReportDetails(t *testing.T) {
	db := openTestDB(t)
	day := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	for _, r := range []RequestLog{
		{Timestamp: day.Add(2 * time.Hour), RealIP: "2.2.2.2", Country: "CN", Blocked: true, RuleID: 941100},
		{Timestamp: day.Add(2*time.Hour + time.Minute), RealIP: "2.2.2.2", Country: "CN", Blocked: true, RuleID: 941100},
		{Timestamp: day.Add(5 * time.Hour), RealIP: "3.3.3.3", Country: "RU", Blocked: true},
		{Timestamp: day.Add(5 * time.Hour), RealIP: "1.1.1.1", Country: "US"},
		{Timestamp: day.Add(-time.Hour), RealIP: "9.9.9.9", Country: "CN", Blocked: true}, // before window
	} {
		r.AppName, r.Method, r.Host, r.Path = "app", "GET", "h", "/"
		if _, err := db.InsertRequest(r); err != nil {
			t.Fatal(err)
		}
	}

	d, err := db.GetReportDetails(day, day.AddDate(0, 0, 1), 5)
	if err != nil {
		t.Fatalf("GetReportDetails: %v", err)
	}
	if len(d.Hourly) != 24 || d.Hourly[2] != (HourlyPoint{day.Add(2 * time.Hour), 2, 2}) || d.Hourly[5].Total != 2 || d.Hourly[5].Blocked != 1 {
		t.Errorf("hourly = %+v", d.Hourly)
	}
	if len(d.TopCountries) != 2 || d.TopCountries[0] != (LabelCount{"CN", 2}) {
		t.Errorf("countries = %+v", d.TopCountries)
	}
	if len(d.TopIPs) != 2 || d.TopIPs[0] != (LabelCount{"2.2.2.2", 2}) {
		t.Errorf("ips = %+v", d.TopIPs)
	}
	if len(d.TopRules) != 1 || d.TopRules[0] != (LabelCount{"941100", 2}) {
		t.Errorf("rules = %+v", d.TopRules)
	}
}
