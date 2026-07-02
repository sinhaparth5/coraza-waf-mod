package storage

import (
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
