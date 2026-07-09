// Package threatscore computes a unified per-IP threat-intelligence score
// (issue #12) by combining signals that today are siloed: autoban's
// existing point history, the bot-analysis score, ASN/hosting
// classification, geo risk, and JA4 fingerprint repeat-offender history.
//
// It is a read model, not an enforcement mechanism — nothing in this
// package blocks or challenges a request. It only computes and persists a
// score (and the per-signal breakdown behind it) so the admin UI can show
// how risky an IP looks. Automated enforcement driven by this score is
// tracked separately (issue #16).
//
// Like autoban.Banner and webhook.Pusher, Scorer.Record is registered as a
// log-worker fan-out hook via storage.DB.SetThreatScoreFn — it runs on the
// single log-worker goroutine, so it must stay fast: an in-memory read of
// autoban's history plus a couple of indexed SQLite writes, no network I/O.
//
// Scoring per event (each component capped, total capped at 100):
//
//	autoban's current point total for the IP   up to 40
//	bot.Analyze score already on the log entry up to 20
//	ASN/org looks like hosting/VPN (asnclass.go) flat 15
//	country has an admin-configured geo block rule flat 10
//	JA4 fingerprint's lifetime blocked-hit count up to 15
package threatscore

import (
	"log"
	"sync"
	"time"

	"coraza-waf-mod/internal/storage"
)

const (
	maxAutobanScore = 40
	maxBotScore     = 20
	asnScore        = 15
	geoRiskScore    = 10
	maxJA4Score     = 15
	ja4ScorePerHit  = 3
)

// store is the subset of *storage.DB the scorer needs — an interface so
// tests can run against a fake without a real database.
type store interface {
	UpsertIPThreatScore(storage.IPThreatScore) error
	BumpJA4Reputation(ja4 string, blocked bool) (hits, blockedHits int, err error)
}

// Scorer accumulates the composite per-IP threat score.
type Scorer struct {
	db           store
	autobanScore func(ip string) int

	mu            sync.RWMutex
	riskCountries map[string]bool

	now func() time.Time // injectable for tests
}

// New builds a Scorer. autobanScore is typically (*autoban.Banner).Score —
// injected rather than imported directly so this package doesn't need to
// know how autoban stores its history, only that it can report a current
// point total for an IP.
func New(db *storage.DB, autobanScore func(ip string) int) *Scorer {
	return &Scorer{
		db:            db,
		autobanScore:  autobanScore,
		riskCountries: make(map[string]bool),
		now:           time.Now,
	}
}

// ReloadGeoRules recomputes the set of countries treated as a geo-risk
// signal, from any admin-configured "block" geo rule (global or per-app).
// Reusing the existing geo_rules table means there's no new admin-facing
// config surface for this — if an admin has already flagged a country as
// block-worthy, that's exactly the "geo risk" signal this component wants.
// Call after every geo-rule change, the same way geo.Blocker.Reload is
// already called, so the risk set stays current without a restart.
func (s *Scorer) ReloadGeoRules(rules []storage.GeoRule) {
	m := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r.RuleType == "block" {
			m[r.CountryCode] = true
		}
	}
	s.mu.Lock()
	s.riskCountries = m
	s.mu.Unlock()
}

// Record computes and persists e's client IP's composite threat score. It
// runs on the storage log-worker goroutine (see the package doc comment).
func (s *Scorer) Record(e storage.RequestLog) {
	if e.RealIP == "" {
		return
	}

	autobanPart := clamp(s.autobanScore(e.RealIP), 0, maxAutobanScore)
	botPart := clamp(e.BotScore, 0, maxBotScore)

	asnPart := 0
	if classify(e.ASN, e.Org) {
		asnPart = asnScore
	}

	geoPart := 0
	s.mu.RLock()
	risky := s.riskCountries[e.Country]
	s.mu.RUnlock()
	if e.Country != "" && risky {
		geoPart = geoRiskScore
	}

	ja4Part := 0
	if e.JA4 != "" {
		if _, blockedHits, err := s.db.BumpJA4Reputation(e.JA4, e.Blocked); err == nil {
			ja4Part = clamp(blockedHits*ja4ScorePerHit, 0, maxJA4Score)
		}
	}

	total := clamp(autobanPart+botPart+asnPart+geoPart+ja4Part, 0, 100)

	err := s.db.UpsertIPThreatScore(storage.IPThreatScore{
		IP:           e.RealIP,
		Total:        total,
		AutobanScore: autobanPart,
		BotScore:     botPart,
		ASNScore:     asnPart,
		GeoScore:     geoPart,
		JA4Score:     ja4Part,
		UpdatedAt:    s.now(),
	})
	if err != nil {
		log.Printf("threatscore: store score for %s: %v", e.RealIP, err)
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
