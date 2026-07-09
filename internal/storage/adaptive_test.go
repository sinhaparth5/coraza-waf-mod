package storage

import (
	"path/filepath"
	"testing"
)

// TestAdaptiveEnforcementConfigRoundtrip mirrors TestAutobanConfigRoundtrip:
// unset reads back as defaults (disabled — see DefaultAdaptiveEnforcementConfig's
// doc comment for why, unlike autoban), and a saved config round-trips
// exactly, including the two float fields.
func TestAdaptiveEnforcementConfigRoundtrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cfg, err := db.GetAdaptiveEnforcementConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg != DefaultAdaptiveEnforcementConfig() {
		t.Errorf("unset config = %+v, want defaults %+v", cfg, DefaultAdaptiveEnforcementConfig())
	}
	if cfg.Enabled {
		t.Error("default adaptive-enforcement config must be disabled (opt-in, unlike autoban)")
	}

	want := AdaptiveEnforcementConfig{
		Enabled: true, HighRiskThreshold: 80, LowRiskThreshold: 5,
		HighRiskRateScale: 0.25, LowRiskRateScale: 2.0, ForceChallengeThreshold: 90,
	}
	if err := db.SetAdaptiveEnforcementConfig(want); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAdaptiveEnforcementConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("roundtrip = %+v, want %+v", got, want)
	}
}
