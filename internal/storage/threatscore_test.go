package storage

import (
	"testing"
	"time"
)

// TestIPThreatScoreRoundtrip exercises Upsert/Get for ip_threat_scores —
// the persistence layer behind the threatscore package's composite per-IP
// score (issue #12).
func TestIPThreatScoreRoundtrip(t *testing.T) {
	db := openTestDB(t)

	if _, ok, err := db.GetIPThreatScore("203.0.113.1"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected no score for an IP with no recorded history")
	}

	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	in := IPThreatScore{
		IP: "203.0.113.1", Total: 57,
		AutobanScore: 30, BotScore: 12, ASNScore: 15, GeoScore: 0, JA4Score: 0,
		UpdatedAt: now,
	}
	if err := db.UpsertIPThreatScore(in); err != nil {
		t.Fatal(err)
	}

	got, ok, err := db.GetIPThreatScore("203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a score after Upsert")
	}
	if got.Total != 57 || got.AutobanScore != 30 || got.BotScore != 12 || got.ASNScore != 15 {
		t.Errorf("got %+v, want Total=57 AutobanScore=30 BotScore=12 ASNScore=15", got)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, now)
	}

	// A second Upsert for the same IP replaces the row rather than adding
	// another one.
	in.Total = 80
	in.UpdatedAt = now.Add(time.Hour)
	if err := db.UpsertIPThreatScore(in); err != nil {
		t.Fatal(err)
	}
	got, _, err = db.GetIPThreatScore("203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 80 {
		t.Errorf("Total after re-upsert = %d, want 80 (replaced, not accumulated)", got.Total)
	}
}

// TestGetIPThreatScoresBulk checks the IP Rules page's bulk lookup: only
// IPs with a recorded score are present in the result, others are simply
// absent (not zero-valued), and an empty input returns an empty map without
// a query.
func TestGetIPThreatScoresBulk(t *testing.T) {
	db := openTestDB(t)

	now := time.Now()
	for ip, score := range map[string]int{"203.0.113.1": 10, "203.0.113.2": 90} {
		if err := db.UpsertIPThreatScore(IPThreatScore{IP: ip, Total: score, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := db.GetIPThreatScores([]string{"203.0.113.1", "203.0.113.2", "203.0.113.3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (unscored IP must be absent, not zero)", len(got))
	}
	if got["203.0.113.1"] != 10 || got["203.0.113.2"] != 90 {
		t.Errorf("got %v, want {203.0.113.1:10 203.0.113.2:90}", got)
	}
	if _, present := got["203.0.113.3"]; present {
		t.Error("unscored IP must be absent from the result map")
	}

	empty, err := db.GetIPThreatScores(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("GetIPThreatScores(nil) = %v, want empty", empty)
	}
}

// TestBumpJA4Reputation checks hits/blocked_hits accumulate correctly
// across repeated calls for the same fingerprint, and that different
// fingerprints don't share counters.
func TestBumpJA4Reputation(t *testing.T) {
	db := openTestDB(t)

	const fp = "t13d1516h2_8daaf6152771_02713d6af862"

	hits, blocked, err := db.BumpJA4Reputation(fp, true)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || blocked != 1 {
		t.Fatalf("first bump: hits=%d blocked=%d, want 1/1", hits, blocked)
	}

	hits, blocked, err = db.BumpJA4Reputation(fp, false)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 2 || blocked != 1 {
		t.Fatalf("second bump (unblocked): hits=%d blocked=%d, want 2/1", hits, blocked)
	}

	hits, blocked, err = db.BumpJA4Reputation(fp, true)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 3 || blocked != 2 {
		t.Fatalf("third bump (blocked): hits=%d blocked=%d, want 3/2", hits, blocked)
	}

	// A different fingerprint starts its own counters from zero.
	otherHits, otherBlocked, err := db.BumpJA4Reputation("other-fp", false)
	if err != nil {
		t.Fatal(err)
	}
	if otherHits != 1 || otherBlocked != 0 {
		t.Fatalf("other fingerprint: hits=%d blocked=%d, want 1/0 (independent counters)", otherHits, otherBlocked)
	}
}
