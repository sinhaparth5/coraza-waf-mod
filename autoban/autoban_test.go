package autoban

import (
	"strings"
	"sync"
	"testing"
	"time"

	"coraza-waf-mod/storage"
)

// fakeStore satisfies the store interface without a database.
type fakeStore struct {
	mu    sync.Mutex
	cfg   storage.AutobanConfig
	rules map[string]string // "app:ip" → rule_type
	notes map[string]string // ip → note
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cfg:   storage.DefaultAutobanConfig(),
		rules: make(map[string]string),
		notes: make(map[string]string),
	}
}

func (f *fakeStore) GetAutobanConfig() (storage.AutobanConfig, error) { return f.cfg, nil }
func (f *fakeStore) GetIPRuleType(appName, ip string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[appName+":"+ip], nil
}
func (f *fakeStore) AddIPRuleWithNote(appName, ip, ruleType, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[appName+":"+ip] = ruleType
	f.notes[ip] = note
	return nil
}

func (f *fakeStore) banNote(ip string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notes[ip]
}

// testBanner builds a Banner with a fixed clock, synchronous ban execution,
// and no janitor goroutine.
func testBanner(db *fakeStore, now time.Time) (*Banner, *[]string) {
	var notified []string
	reloads := 0
	b := &Banner{
		db:     db,
		reload: func() { reloads++ },
		notify: func(ip, reason string) { notified = append(notified, ip+" | "+reason) },
		hist:   make(map[string][]event),
		banned: make(map[string]time.Time),
		stop:   make(chan struct{}),
		now:    func() time.Time { return now },
		spawn:  func(fn func()) { fn() }, // synchronous in tests
	}
	b.ReloadConfig()
	return b, &notified
}

func blockedEvent(ip, action string, ruleID int, at time.Time) storage.RequestLog {
	return storage.RequestLog{Timestamp: at, RealIP: ip, Blocked: true, Action: action, RuleID: ruleID, Status: 403}
}

func TestSevereAttackBansQuickly(t *testing.T) {
	db := newFakeStore()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	b, notified := testBanner(db, now)

	// Two SQLi-class hits (942100) = 10 points = default threshold.
	b.Record(blockedEvent("203.0.113.7", "deny", 942100, now))
	b.Record(blockedEvent("203.0.113.7", "deny", 942100, now.Add(time.Second)))

	if got := db.rules[":203.0.113.7"]; got != "block" {
		t.Fatalf("rule = %q, want block", got)
	}
	note := db.banNote("203.0.113.7")
	if !strings.HasPrefix(note, "Auto-banned — ") || !strings.Contains(note, "2 critical WAF hits") {
		t.Errorf("note = %q, want Auto-banned prefix and critical-hit breakdown", note)
	}
	if len(*notified) != 1 || !strings.Contains((*notified)[0], "203.0.113.7") {
		t.Errorf("notified = %v, want exactly one alert for the banned IP", *notified)
	}
}

func TestRepeatOffenderRateLimitedBans(t *testing.T) {
	db := newFakeStore()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	b, notified := testBanner(db, now)

	for i := 0; i < 10; i++ {
		b.Record(blockedEvent("198.51.100.9", "rate_limited", 0, now.Add(time.Duration(i)*time.Second)))
	}
	if db.rules[":198.51.100.9"] != "block" {
		t.Fatal("10 rate-limited requests in the window should ban")
	}
	if len(*notified) != 1 {
		t.Fatalf("notified %d times, want 1", len(*notified))
	}

	// Further blocked events for the same IP must not re-ban or re-notify.
	b.Record(blockedEvent("198.51.100.9", "rate_limited", 0, now.Add(time.Minute)))
	if len(*notified) != 1 {
		t.Errorf("duplicate ban alert sent")
	}
}

func TestEventsOutsideWindowDoNotCount(t *testing.T) {
	db := newFakeStore()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	b, _ := testBanner(db, now)

	// 9 rate-limited events 11 minutes ago are outside the 10-minute window.
	old := now.Add(-11 * time.Minute)
	for i := 0; i < 9; i++ {
		b.hist["198.51.100.9"] = append(b.hist["198.51.100.9"], event{t: old, pts: ptsRateLimited, rl: true})
	}
	b.Record(blockedEvent("198.51.100.9", "rate_limited", 0, now))
	if db.rules[":198.51.100.9"] != "" {
		t.Fatal("stale events outside the window must not contribute to a ban")
	}
}

func TestNeverBansPrivateOrAlreadyHandledIPs(t *testing.T) {
	db := newFakeStore()
	db.rules[":203.0.113.50"] = "allow" // admin allow rule
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	b, notified := testBanner(db, now)

	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.5", "fe80::1", "", "not-an-ip"} {
		for i := 0; i < 5; i++ {
			b.Record(blockedEvent(ip, "deny", 942100, now))
		}
		if db.rules[":"+ip] == "block" {
			t.Errorf("banned unbannable address %q", ip)
		}
	}

	// Allow-listed IP: threshold crossing must not overwrite the admin rule.
	for i := 0; i < 5; i++ {
		b.Record(blockedEvent("203.0.113.50", "deny", 942100, now))
	}
	if db.rules[":203.0.113.50"] != "allow" {
		t.Error("auto-ban overwrote an admin allow rule")
	}
	if len(*notified) != 0 {
		t.Errorf("alerts sent for unbannable IPs: %v", *notified)
	}
}

func TestAlreadyBlockedTrafficNeverScores(t *testing.T) {
	db := newFakeStore()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	b, notified := testBanner(db, now)

	for i := 0; i < 50; i++ {
		b.Record(blockedEvent("203.0.113.8", "ip_blocked_global", 0, now))
		b.Record(blockedEvent("203.0.113.8", "ip_blocked_intel", 0, now))
		b.Record(blockedEvent("203.0.113.8", "geo_blocked:CN", 0, now))
	}
	if len(b.hist["203.0.113.8"]) != 0 || len(*notified) != 0 {
		t.Fatal("already-blocked traffic must not score or alert")
	}
}

func TestDisabledConfigNeverBans(t *testing.T) {
	db := newFakeStore()
	db.cfg.Enabled = false
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	b, _ := testBanner(db, now)

	for i := 0; i < 20; i++ {
		b.Record(blockedEvent("203.0.113.9", "deny", 942100, now))
	}
	if len(db.rules) != 0 {
		t.Fatal("disabled autoban still created rules")
	}
}

func TestCriticalRuleRanges(t *testing.T) {
	for id, want := range map[int]bool{
		930100: true,  // LFI
		932160: true,  // RCE
		941100: true,  // XSS
		942100: true,  // SQLi
		944100: true,  // Java injection
		920350: false, // protocol enforcement
		949110: false, // anomaly evaluation
		913100: false, // scanner detection
	} {
		if got := criticalRule(id); got != want {
			t.Errorf("criticalRule(%d) = %v, want %v", id, got, want)
		}
	}
}
