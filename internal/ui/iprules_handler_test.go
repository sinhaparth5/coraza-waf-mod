package ui

import (
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/storage"
)

// TestIPRulesRowsDataClamping exercises ipRulesRowsData's page-clamping —
// the logic DeleteIPRule relies on so deleting the last row on a page (or an
// admin's browser holding a stale ?page= after other rows were removed)
// falls back to the new last page instead of rendering an empty one.
func TestIPRulesRowsDataClamping(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if err := db.AddIPRule("", ip, "block"); err != nil {
			t.Fatal(err)
		}
	}

	h := &Handler{cfg: &config.Config{Admin: config.AdminConfig{Path: "/admin"}}, db: db}

	// Normal in-range page.
	data, err := h.ipRulesRowsData(1)
	if err != nil {
		t.Fatal(err)
	}
	if data["Total"] != 3 || data["CurPage"] != 1 || data["TotalPages"] != 1 {
		t.Fatalf("page 1 data = %+v, want Total=3 CurPage=1 TotalPages=1", data)
	}
	if rules, ok := data["Rules"].([]storage.IPRule); !ok || len(rules) != 3 {
		t.Fatalf("page 1 Rules = %v, want all 3 rows (page size > row count)", data["Rules"])
	}

	// Way out of range (e.g. a stale ?page= from before other rows were
	// deleted) must clamp down to the real last page, not render empty.
	data, err = h.ipRulesRowsData(5)
	if err != nil {
		t.Fatal(err)
	}
	if data["CurPage"] != 1 || data["TotalPages"] != 1 {
		t.Fatalf("out-of-range page data = %+v, want clamped to CurPage=1 TotalPages=1", data)
	}
	if rules, ok := data["Rules"].([]storage.IPRule); !ok || len(rules) != 3 {
		t.Fatalf("clamped page Rules = %v, want all 3 rows, not empty", data["Rules"])
	}

	// Below range (page 0 or negative) must clamp up to page 1, not error or
	// pass a negative offset to the DB query.
	data, err = h.ipRulesRowsData(0)
	if err != nil {
		t.Fatal(err)
	}
	if data["CurPage"] != 1 {
		t.Fatalf("page 0 data CurPage = %v, want clamped to 1", data["CurPage"])
	}
}

// TestIPRulesRowsDataIncludesThreatScores checks ipRulesRowsData bulk-fetches
// the current page's threat scores (issue #12) in one call rather than
// leaving the UI to look them up per row, and that an IP with no recorded
// score is simply absent rather than reported as zero.
func TestIPRulesRowsDataIncludesThreatScores(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.AddIPRule("", "10.0.0.1", "block"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddIPRule("", "10.0.0.2", "block"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertIPThreatScore(storage.IPThreatScore{IP: "10.0.0.1", Total: 42}); err != nil {
		t.Fatal(err)
	}

	h := &Handler{cfg: &config.Config{Admin: config.AdminConfig{Path: "/admin"}}, db: db}
	data, err := h.ipRulesRowsData(1)
	if err != nil {
		t.Fatal(err)
	}

	scores, ok := data["ThreatScores"].(map[string]int)
	if !ok {
		t.Fatalf("ThreatScores missing or wrong type: %v", data["ThreatScores"])
	}
	if scores["10.0.0.1"] != 42 {
		t.Errorf("ThreatScores[10.0.0.1] = %d, want 42", scores["10.0.0.1"])
	}
	if _, present := scores["10.0.0.2"]; present {
		t.Error("10.0.0.2 has no recorded score and must be absent, not zero")
	}
}
