package threatscore

import (
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

// fakeStore satisfies the store interface without a database.
type fakeStore struct {
	scores map[string]storage.IPThreatScore
	ja4    map[string][2]int // ja4 -> [hits, blockedHits]
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		scores: make(map[string]storage.IPThreatScore),
		ja4:    make(map[string][2]int),
	}
}

func (f *fakeStore) UpsertIPThreatScore(s storage.IPThreatScore) error {
	f.scores[s.IP] = s
	return nil
}

func (f *fakeStore) BumpJA4Reputation(ja4 string, blocked bool) (hits, blockedHits int, err error) {
	c := f.ja4[ja4]
	c[0]++
	if blocked {
		c[1]++
	}
	f.ja4[ja4] = c
	return c[0], c[1], nil
}

func testScorer(db *fakeStore, autobanScore func(string) int) *Scorer {
	if autobanScore == nil {
		autobanScore = func(string) int { return 0 }
	}
	return &Scorer{
		db:            db,
		autobanScore:  autobanScore,
		riskCountries: make(map[string]bool),
		scores:        make(map[string]int),
		lastSeen:      make(map[string]time.Time),
		now:           func() time.Time { return time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC) },
	}
}

func TestRecordSkipsWithoutRealIP(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)
	s.Record(storage.RequestLog{RealIP: "", BotScore: 50})
	if len(db.scores) != 0 {
		t.Fatal("Record must skip entries with no RealIP")
	}
}

func TestRecordCombinesAllFiveComponents(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, func(ip string) int { return 30 }) // -> clamped 30 (under cap 40)
	s.ReloadGeoRules([]storage.GeoRule{{CountryCode: "CN", RuleType: "block"}})

	e := storage.RequestLog{
		RealIP:   "203.0.113.5",
		BotScore: 12,
		ASN:      16509, // Amazon AWS — in the hosting heuristic list
		Org:      "Amazon.com, Inc.",
		Country:  "CN", // matches the configured geo-risk rule
		JA4:      "t13d1516h2_8daaf6152771_02713d6af862",
		Blocked:  true,
	}
	s.Record(e)

	got, ok := db.scores["203.0.113.5"]
	if !ok {
		t.Fatal("no score recorded")
	}
	if got.AutobanScore != 30 {
		t.Errorf("AutobanScore = %d, want 30", got.AutobanScore)
	}
	if got.BotScore != 12 {
		t.Errorf("BotScore = %d, want 12", got.BotScore)
	}
	if got.ASNScore != asnScore {
		t.Errorf("ASNScore = %d, want %d (hosting ASN)", got.ASNScore, asnScore)
	}
	if got.GeoScore != geoRiskScore {
		t.Errorf("GeoScore = %d, want %d (CN is risk-listed)", got.GeoScore, geoRiskScore)
	}
	// First-ever hit for this JA4, and it's blocked: blockedHits=1 -> 1*3=3.
	if got.JA4Score != ja4ScorePerHit {
		t.Errorf("JA4Score = %d, want %d (first blocked hit)", got.JA4Score, ja4ScorePerHit)
	}
	wantTotal := 30 + 12 + asnScore + geoRiskScore + ja4ScorePerHit
	if got.Total != wantTotal {
		t.Errorf("Total = %d, want %d", got.Total, wantTotal)
	}
}

func TestAutobanAndBotComponentsClamp(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, func(string) int { return 999 }) // way over the cap

	s.Record(storage.RequestLog{RealIP: "203.0.113.6", BotScore: 999})

	got := db.scores["203.0.113.6"]
	if got.AutobanScore != maxAutobanScore {
		t.Errorf("AutobanScore = %d, want clamped to %d", got.AutobanScore, maxAutobanScore)
	}
	if got.BotScore != maxBotScore {
		t.Errorf("BotScore = %d, want clamped to %d", got.BotScore, maxBotScore)
	}
	if got.Total != maxAutobanScore+maxBotScore {
		t.Errorf("Total = %d, want %d", got.Total, maxAutobanScore+maxBotScore)
	}
}

func TestASNClassificationResidentialISPScoresZero(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)

	s.Record(storage.RequestLog{RealIP: "203.0.113.7", ASN: 7922, Org: "Comcast Cable Communications"})

	got := db.scores["203.0.113.7"]
	if got.ASNScore != 0 {
		t.Errorf("ASNScore = %d, want 0 for a residential ISP", got.ASNScore)
	}
}

func TestGeoRiskOnlyAppliesToConfiguredRules(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)
	s.ReloadGeoRules([]storage.GeoRule{
		{CountryCode: "RU", RuleType: "block"},
		{CountryCode: "DE", RuleType: "allow"}, // allow rule must NOT count as risk
	})

	s.Record(storage.RequestLog{RealIP: "203.0.113.8", Country: "RU"})
	if got := db.scores["203.0.113.8"].GeoScore; got != geoRiskScore {
		t.Errorf("RU GeoScore = %d, want %d", got, geoRiskScore)
	}

	s.Record(storage.RequestLog{RealIP: "203.0.113.9", Country: "DE"})
	if got := db.scores["203.0.113.9"].GeoScore; got != 0 {
		t.Errorf("DE (allow rule) GeoScore = %d, want 0", got)
	}

	s.Record(storage.RequestLog{RealIP: "203.0.113.10", Country: "FR"})
	if got := db.scores["203.0.113.10"].GeoScore; got != 0 {
		t.Errorf("FR (unconfigured) GeoScore = %d, want 0", got)
	}
}

// TestReloadGeoRulesReplacesPreviousSet checks a reload (e.g. after an admin
// removes a geo rule) drops the old risk set rather than merging into it.
func TestReloadGeoRulesReplacesPreviousSet(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)
	s.ReloadGeoRules([]storage.GeoRule{{CountryCode: "CN", RuleType: "block"}})
	s.ReloadGeoRules([]storage.GeoRule{{CountryCode: "RU", RuleType: "block"}})

	s.Record(storage.RequestLog{RealIP: "203.0.113.11", Country: "CN"})
	if got := db.scores["203.0.113.11"].GeoScore; got != 0 {
		t.Errorf("stale CN rule still scoring after reload: GeoScore = %d, want 0", got)
	}
}

// TestJA4RepeatOffenderAccumulatesAndCaps checks the JA4 component grows
// with repeated blocked hits on the same fingerprint (even across different
// IPs — that's the point of a fingerprint-keyed reputation) and caps out.
func TestJA4RepeatOffenderAccumulatesAndCaps(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)
	const fp = "t13d1516h2_8daaf6152771_02713d6af862"

	ips := []string{"203.0.113.12", "203.0.113.13", "203.0.113.14", "203.0.113.15", "203.0.113.16", "203.0.113.17"}
	for _, ip := range ips {
		s.Record(storage.RequestLog{RealIP: ip, JA4: fp, Blocked: true})
	}

	// 6th blocked hit -> blockedHits=6 -> 6*3=18, clamped to maxJA4Score.
	got := db.scores["203.0.113.17"].JA4Score
	if got != maxJA4Score {
		t.Errorf("JA4Score after 6 blocked hits = %d, want clamped to %d", got, maxJA4Score)
	}

	// A non-blocked hit on the same fingerprint bumps hits but not
	// blockedHits, so the score component doesn't change.
	s.Record(storage.RequestLog{RealIP: "203.0.113.18", JA4: fp, Blocked: false})
	if got := db.scores["203.0.113.18"].JA4Score; got != maxJA4Score {
		t.Errorf("JA4Score after an unblocked hit = %d, want unchanged at %d", got, maxJA4Score)
	}
}

func TestEmptyJA4ScoresZeroAndSkipsReputationLookup(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)
	s.Record(storage.RequestLog{RealIP: "203.0.113.19", JA4: "", Blocked: true})

	if got := db.scores["203.0.113.19"].JA4Score; got != 0 {
		t.Errorf("JA4Score with no fingerprint = %d, want 0", got)
	}
	if len(db.ja4) != 0 {
		t.Error("BumpJA4Reputation must not be called for an empty JA4")
	}
}

func TestTotalScoreNeverExceeds100(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, func(string) int { return 1000 })
	s.ReloadGeoRules([]storage.GeoRule{{CountryCode: "CN", RuleType: "block"}})

	// Prime the JA4 fingerprint's reputation past the cap first.
	const fp = "t13d1516h2_8daaf6152771_02713d6af862"
	for i := 0; i < 10; i++ {
		if _, _, err := db.BumpJA4Reputation(fp, true); err != nil {
			t.Fatal(err)
		}
	}

	s.Record(storage.RequestLog{
		RealIP: "203.0.113.99", BotScore: 1000, ASN: 16509, Org: "Amazon",
		Country: "CN", JA4: fp, Blocked: true,
	})

	if got := db.scores["203.0.113.99"].Total; got != 100 {
		t.Errorf("Total = %d, want capped at 100", got)
	}
}

// TestCurrentScoreReflectsLastRecord checks the in-memory cache CurrentScore
// reads from (issue #16's hot-path lookup) tracks the most recent Record
// call, not a stale earlier one.
func TestCurrentScoreReflectsLastRecord(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, func(string) int { return 10 })

	if got := s.CurrentScore("203.0.113.30"); got != 0 {
		t.Fatalf("CurrentScore before any Record = %d, want 0", got)
	}

	s.Record(storage.RequestLog{RealIP: "203.0.113.30", BotScore: 5})
	first := s.CurrentScore("203.0.113.30")
	if first != 15 { // autoban 10 + bot 5
		t.Fatalf("CurrentScore after first Record = %d, want 15", first)
	}

	s.Record(storage.RequestLog{RealIP: "203.0.113.30", BotScore: 20})
	second := s.CurrentScore("203.0.113.30")
	if second != 30 { // autoban 10 + bot 20
		t.Fatalf("CurrentScore after second Record = %d, want 30 (latest, not stale first value)", second)
	}
}

// TestCurrentScoreUnknownIPIsZero checks an IP that has never been scored
// reads as 0, not an error or panic — the "no data yet" case adaptive.Decide
// must treat as normal risk.
func TestCurrentScoreUnknownIPIsZero(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)
	s.Record(storage.RequestLog{RealIP: "203.0.113.31"})

	if got := s.CurrentScore("203.0.113.32"); got != 0 {
		t.Errorf("CurrentScore for a never-seen IP = %d, want 0", got)
	}
}

// TestCurrentScoreNilScorerIsZero checks a nil *Scorer (e.g. a test Handler
// built without one) doesn't panic — mirrors asn.Lookup's nil-receiver
// guard, the established pattern in this codebase for optional deps.
func TestCurrentScoreNilScorerIsZero(t *testing.T) {
	var s *Scorer
	if got := s.CurrentScore("203.0.113.33"); got != 0 {
		t.Errorf("nil Scorer CurrentScore = %d, want 0", got)
	}
}

// TestJanitorEvictsIdleScores mirrors ratelimit.TestJanitorEvictsIdleBuckets:
// simulates the janitor's eviction pass directly (no live ticker) by forcing
// a cutoff far in the future so every entry counts as idle.
func TestJanitorEvictsIdleScores(t *testing.T) {
	db := newFakeStore()
	s := testScorer(db, nil)

	s.Record(storage.RequestLog{RealIP: "203.0.113.40"})
	s.Record(storage.RequestLog{RealIP: "203.0.113.41"})
	if got := len(s.scores); got != 2 {
		t.Fatalf("expected 2 cached scores before eviction, got %d", got)
	}

	cutoff := s.now().Add(time.Hour)
	s.mu.Lock()
	for ip, t := range s.lastSeen {
		if t.Before(cutoff) {
			delete(s.lastSeen, ip)
			delete(s.scores, ip)
		}
	}
	s.mu.Unlock()

	if len(s.scores) != 0 || len(s.lastSeen) != 0 {
		t.Fatalf("expected empty caches after eviction, got scores=%d lastSeen=%d", len(s.scores), len(s.lastSeen))
	}
	if got := s.CurrentScore("203.0.113.40"); got != 0 {
		t.Errorf("evicted IP CurrentScore = %d, want 0", got)
	}
}
