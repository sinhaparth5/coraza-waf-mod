package storage

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestIPRuleNoteRoundtrip exercises the note column added for auto-bans:
// upsert with a note, list it back, exact-rule lookup, and the Auto flag the
// IP Rules template renders the badge from.
func TestIPRuleNoteRoundtrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.AddIPRule("", "1.2.3.4", "allow"); err != nil {
		t.Fatal(err)
	}
	note := "Auto-banned — 12 blocked requests in 10 min (2 critical WAF hits)"
	if err := db.AddIPRuleWithNote("", "203.0.113.7", "block", note); err != nil {
		t.Fatal(err)
	}

	rules, err := db.ListIPRules()
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]IPRule{}
	for _, r := range rules {
		byIP[r.IP] = r
	}
	if got := byIP["203.0.113.7"]; got.Note != note || !got.Auto() || got.RuleType != "block" {
		t.Errorf("banned rule = %+v, want block rule with note and Auto()=true", got)
	}
	if got := byIP["1.2.3.4"]; got.Note != "" || got.Auto() {
		t.Errorf("manual rule = %+v, want empty note and Auto()=false", got)
	}

	for ip, want := range map[string]string{
		"1.2.3.4":     "allow",
		"203.0.113.7": "block",
		"9.9.9.9":     "", // absent → no error, empty type
	} {
		got, err := db.GetIPRuleType("", ip)
		if err != nil || got != want {
			t.Errorf("GetIPRuleType(%q) = %q, %v; want %q, nil", ip, got, err, want)
		}
	}
}

// TestListIPRulesPaginated exercises the paginated query added for the IP
// Rules admin page (a large autoban-grown table previously loaded in full on
// every view and every add/delete): page slicing, the total count staying
// accurate regardless of page, and an out-of-range offset returning no rows
// without erroring.
func TestListIPRulesPaginated(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Insert 5 rules with distinct IPs. created_at defaults to SQLite's
	// CURRENT_TIMESTAMP, which only has second resolution, so rows inserted
	// in the same test run can tie on created_at — this test therefore checks
	// page sizes and full coverage across pages via set membership, not a
	// specific tie-break order.
	wantIPs := map[string]bool{}
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		wantIPs[ip] = true
		if err := db.AddIPRule("", ip, "block"); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]bool{}
	pages := [][2]int{{0, 2}, {2, 2}, {4, 2}} // offset, limit — 2+2+1 across 3 pages
	wantLens := []int{2, 2, 1}
	for i, p := range pages {
		rules, total, err := db.ListIPRulesPaginated(p[1], p[0])
		if err != nil {
			t.Fatal(err)
		}
		if total != 5 {
			t.Fatalf("total on page offset=%d = %d, want 5 (must reflect the whole table, not the page)", p[0], total)
		}
		if len(rules) != wantLens[i] {
			t.Fatalf("page offset=%d limit=%d returned %d rows, want %d", p[0], p[1], len(rules), wantLens[i])
		}
		for _, r := range rules {
			if seen[r.IP] {
				t.Fatalf("IP %s returned on more than one page — offset/limit slicing overlapped", r.IP)
			}
			seen[r.IP] = true
		}
	}
	if len(seen) != len(wantIPs) {
		t.Fatalf("pages covered %d distinct IPs, want all %d: seen=%v", len(seen), len(wantIPs), seen)
	}
	for ip := range wantIPs {
		if !seen[ip] {
			t.Errorf("IP %s never appeared on any page", ip)
		}
	}

	// Past the end: no rows, no error, total still accurate.
	rules, total, err := db.ListIPRulesPaginated(2, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("total past the end = %d, want 5", total)
	}
	if len(rules) != 0 {
		t.Fatalf("rules past the end = %+v, want empty", rules)
	}
}

// TestCountIPRulesByType checks the global block/allow counts used by the IP
// Rules page's "Rules overview" percentages reflect the whole table, which
// matters once the row list itself is paginated and can no longer be summed
// client-side from the current page alone.
func TestCountIPRulesByType(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	block, allow, err := db.CountIPRulesByType()
	if err != nil {
		t.Fatal(err)
	}
	if block != 0 || allow != 0 {
		t.Fatalf("empty table counts = (%d, %d), want (0, 0)", block, allow)
	}

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if err := db.AddIPRule("", ip, "block"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddIPRule("", "10.0.0.9", "allow"); err != nil {
		t.Fatal(err)
	}

	block, allow, err = db.CountIPRulesByType()
	if err != nil {
		t.Fatal(err)
	}
	if block != 3 || allow != 1 {
		t.Fatalf("counts = (%d, %d), want (3, 1)", block, allow)
	}
}

func TestAutobanConfigRoundtrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Nothing stored yet: defaults (enabled).
	cfg, err := db.GetAutobanConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg != DefaultAutobanConfig() {
		t.Errorf("unset config = %+v, want defaults %+v", cfg, DefaultAutobanConfig())
	}

	want := AutobanConfig{Enabled: false, Threshold: 25, WindowMinutes: 30}
	if err := db.SetAutobanConfig(want); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetAutobanConfig(); got != want {
		t.Errorf("roundtrip = %+v, want %+v", got, want)
	}
}
