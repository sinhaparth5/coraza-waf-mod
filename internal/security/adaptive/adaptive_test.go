package adaptive

import (
	"testing"

	"coraza-waf-mod/internal/storage"
)

// fakeStore satisfies the store interface without a database.
type fakeStore struct {
	cfg storage.AdaptiveEnforcementConfig
}

func (f *fakeStore) GetAdaptiveEnforcementConfig() (storage.AdaptiveEnforcementConfig, error) {
	return f.cfg, nil
}

func testPolicy(cfg storage.AdaptiveEnforcementConfig) *Policy {
	return &Policy{db: &fakeStore{cfg: cfg}, cfg: cfg}
}

var enabledCfg = storage.AdaptiveEnforcementConfig{
	Enabled: true, HighRiskThreshold: 70, LowRiskThreshold: 10,
	HighRiskRateScale: 0.3, LowRiskRateScale: 1.5, ForceChallengeThreshold: 85,
}

func TestDecideDisabledAlwaysUnscaled(t *testing.T) {
	cfg := enabledCfg
	cfg.Enabled = false
	p := testPolicy(cfg)

	for _, score := range []int{0, 50, 70, 100} {
		d := p.Decide(score)
		if d.RateScale != 1.0 || d.ForceChallenge || d.Tier != "" {
			t.Errorf("score %d: disabled config must return unscaled, got %+v", score, d)
		}
	}
}

func TestDecideHighRiskTierScalesDown(t *testing.T) {
	p := testPolicy(enabledCfg)

	d := p.Decide(70) // exactly at threshold
	if d.RateScale != enabledCfg.HighRiskRateScale {
		t.Errorf("RateScale = %v, want %v", d.RateScale, enabledCfg.HighRiskRateScale)
	}
	if d.Tier != "high" {
		t.Errorf("Tier = %q, want %q", d.Tier, "high")
	}
	if d.ForceChallenge {
		t.Error("score 70 is below ForceChallengeThreshold 85, must not force a challenge")
	}
}

func TestDecideForceChallengeOnlyPastSeparateThreshold(t *testing.T) {
	p := testPolicy(enabledCfg)

	// Just below the force-challenge threshold: tightened rate, no challenge.
	if d := p.Decide(84); d.ForceChallenge {
		t.Error("score 84 is below ForceChallengeThreshold 85, must not force a challenge")
	}
	// At the threshold: both.
	d := p.Decide(85)
	if !d.ForceChallenge {
		t.Error("score 85 meets ForceChallengeThreshold, must force a challenge")
	}
	if d.RateScale != enabledCfg.HighRiskRateScale {
		t.Errorf("RateScale at score 85 = %v, want %v", d.RateScale, enabledCfg.HighRiskRateScale)
	}
}

func TestDecideLowRiskTierScalesUpNeverChallenges(t *testing.T) {
	p := testPolicy(enabledCfg)

	d := p.Decide(10) // exactly at threshold
	if d.RateScale != enabledCfg.LowRiskRateScale {
		t.Errorf("RateScale = %v, want %v", d.RateScale, enabledCfg.LowRiskRateScale)
	}
	if d.Tier != "low" {
		t.Errorf("Tier = %q, want %q", d.Tier, "low")
	}
	if d.ForceChallenge {
		t.Error("low-risk tier must never force a challenge")
	}
}

func TestDecideNormalTierUnscaled(t *testing.T) {
	p := testPolicy(enabledCfg)

	// Strictly between the two thresholds (10 < score < 70).
	for _, score := range []int{11, 40, 69} {
		d := p.Decide(score)
		if d.RateScale != 1.0 || d.ForceChallenge || d.Tier != "" {
			t.Errorf("score %d (normal tier): want unscaled, got %+v", score, d)
		}
	}
}

// TestDecideNilPolicyIsUnscaled mirrors threatscore.Scorer's nil-receiver
// guard — a Handler built without a Policy (e.g. in tests) must not panic.
func TestDecideNilPolicyIsUnscaled(t *testing.T) {
	var p *Policy
	d := p.Decide(100)
	if d.RateScale != 1.0 || d.ForceChallenge {
		t.Errorf("nil Policy Decide = %+v, want unscaled", d)
	}
}

func TestReloadConfigPicksUpChanges(t *testing.T) {
	store := &fakeStore{cfg: storage.AdaptiveEnforcementConfig{Enabled: false}}
	p := New(store)

	if d := p.Decide(90); d.RateScale != 1.0 {
		t.Fatalf("initial config disabled: RateScale = %v, want 1.0", d.RateScale)
	}

	store.cfg = enabledCfg
	p.ReloadConfig()

	if d := p.Decide(90); d.RateScale != enabledCfg.HighRiskRateScale {
		t.Fatalf("after ReloadConfig: RateScale = %v, want %v", d.RateScale, enabledCfg.HighRiskRateScale)
	}
}
