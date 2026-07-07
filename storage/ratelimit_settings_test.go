package storage

import (
	"path/filepath"
	"testing"
)

func TestRateLimitSettingsRoundtrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Unset: disabled with the documented defaults.
	enabled, rps, burst, err := db.GetRateLimitSettings()
	if err != nil {
		t.Fatal(err)
	}
	if enabled || rps != 10 || burst != 20 {
		t.Errorf("unset settings = %v/%g/%d, want disabled/10/20", enabled, rps, burst)
	}

	if err := db.SetRateLimitSettings(true, 2.5, 40); err != nil {
		t.Fatal(err)
	}
	enabled, rps, burst, _ = db.GetRateLimitSettings()
	if !enabled || rps != 2.5 || burst != 40 {
		t.Errorf("roundtrip = %v/%g/%d, want enabled/2.5/40", enabled, rps, burst)
	}

	// Non-positive stored values are ignored in favor of defaults.
	if err := db.SetRateLimitSettings(false, 0, 0); err != nil {
		t.Fatal(err)
	}
	enabled, rps, burst, _ = db.GetRateLimitSettings()
	if enabled || rps != 10 || burst != 20 {
		t.Errorf("zeroed settings = %v/%g/%d, want disabled/10/20", enabled, rps, burst)
	}
}
