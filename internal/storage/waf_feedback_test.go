package storage

import "testing"

// TestWAFRuleFeedbackConfigDefaultsAndRoundtrip mirrors the AutobanConfig
// precedent: default when nothing is stored, then persisted after Set.
func TestWAFRuleFeedbackConfigDefaultsAndRoundtrip(t *testing.T) {
	db := openTestDB(t)

	cfg, err := db.GetWAFRuleFeedbackConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Threshold != 5 || cfg.WindowDays != 7 {
		t.Fatalf("default config = %+v, want threshold=5 window=7", cfg)
	}

	if err := db.SetWAFRuleFeedbackConfig(WAFRuleFeedbackConfig{Threshold: 3, WindowDays: 14}); err != nil {
		t.Fatal(err)
	}
	cfg, err = db.GetWAFRuleFeedbackConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Threshold != 3 || cfg.WindowDays != 14 {
		t.Fatalf("after Set: config = %+v, want threshold=3 window=14", cfg)
	}
}

// TestGetWAFRuleSuggestionsThresholdAndTruePositive verifies a rule is only
// suggested once it crosses the false-positive threshold with zero
// true-positive marks in the window, and drops out again once a true
// positive is recorded.
func TestGetWAFRuleSuggestionsThresholdAndTruePositive(t *testing.T) {
	db := openTestDB(t)
	cfg := WAFRuleFeedbackConfig{Threshold: 2, WindowDays: 7}

	if err := db.MarkWAFRuleFeedback("api", 942100, true); err != nil {
		t.Fatal(err)
	}
	suggestions, err := db.GetWAFRuleSuggestions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestions) != 0 {
		t.Fatalf("below threshold: suggestions = %+v, want none", suggestions)
	}

	if err := db.MarkWAFRuleFeedback("api", 942100, true); err != nil {
		t.Fatal(err)
	}
	suggestions, err = db.GetWAFRuleSuggestions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestions) != 1 || suggestions[0].ServiceName != "api" || suggestions[0].RuleID != 942100 || suggestions[0].FalsePositiveCount != 2 {
		t.Fatalf("at threshold: suggestions = %+v, want one for api/942100 with count 2", suggestions)
	}

	if err := db.MarkWAFRuleFeedback("api", 942100, false); err != nil {
		t.Fatal(err)
	}
	suggestions, err = db.GetWAFRuleSuggestions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestions) != 0 {
		t.Fatalf("after a true-positive mark: suggestions = %+v, want none", suggestions)
	}
}

// TestGetWAFRuleSuggestionsExcludesExistingExceptions verifies a rule
// already suppressed for a service (or globally) never gets suggested again
// — that button would be a dead end.
func TestGetWAFRuleSuggestionsExcludesExistingExceptions(t *testing.T) {
	db := openTestDB(t)
	cfg := WAFRuleFeedbackConfig{Threshold: 1, WindowDays: 7}

	if err := db.MarkWAFRuleFeedback("api", 942100, true); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkWAFRuleFeedback("", 921100, true); err != nil {
		t.Fatal(err)
	}

	if err := db.DisableWAFRuleForService("api", 942100, "already excepted"); err != nil {
		t.Fatal(err)
	}
	if err := db.DisableWAFRule(921100, "already global"); err != nil {
		t.Fatal(err)
	}

	suggestions, err := db.GetWAFRuleSuggestions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestions) != 0 {
		t.Fatalf("suggestions = %+v, want none once exceptions exist", suggestions)
	}
}
