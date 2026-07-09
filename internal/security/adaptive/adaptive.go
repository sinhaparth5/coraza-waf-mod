// Package adaptive turns a client's composite threat score (threatscore
// package, issue #12) into an enforcement decision — how much to scale the
// global rate limit and whether to force a bot challenge — for
// threat-score-driven adaptive enforcement (issue #16).
//
// This package is policy only, not mechanism: Decide is a pure function of
// score and the current config, with no I/O and no side effects, safe to
// call on every request. It is deliberately separate from threatscore
// (which only computes the score) and from ratelimit/challenge (which only
// enforce) — the same separation-of-concerns split this codebase already
// uses between blocklist (data) and the proxy handler (decision).
//
// Because every decision re-reads the client's *current* score, enforcement
// here is inherently reversible: a request from an IP whose score has since
// dropped is judged on the new score, not a snapshot. Contrast with
// autoban's permanent block rule, which requires an explicit admin/API
// removal once written.
package adaptive

import (
	"log"
	"sync"

	"coraza-waf-mod/internal/storage"
)

// store is the subset of *storage.DB the policy needs — an interface so
// tests can run against a fake without a real database.
type store interface {
	GetAdaptiveEnforcementConfig() (storage.AdaptiveEnforcementConfig, error)
}

// Policy holds the current adaptive-enforcement config, reloadable from the
// DB without a restart — same swap pattern as autoban.Banner.ReloadConfig.
type Policy struct {
	db store

	mu  sync.RWMutex
	cfg storage.AdaptiveEnforcementConfig
}

// New builds a Policy and loads the current config from db.
func New(db store) *Policy {
	p := &Policy{db: db}
	p.ReloadConfig()
	return p
}

// ReloadConfig re-reads the adaptive-enforcement settings from the DB.
// Called by the UI save handler so changes apply without a restart.
func (p *Policy) ReloadConfig() {
	cfg, err := p.db.GetAdaptiveEnforcementConfig()
	if err != nil {
		log.Printf("adaptive: read config: %v", err)
		return
	}
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
}

// Decision is what a client's current threat score implies for enforcement.
type Decision struct {
	RateScale      float64 // multiplies the global rate limit's rate+burst; 1.0 = unchanged
	ForceChallenge bool    // force a bot challenge regardless of per-service bot_mode
	Tier           string  // "high", "low", or "" (normal) — for log/response transparency
}

// unscaled is returned whenever adaptive enforcement doesn't apply — a
// package-level value since it never varies.
var unscaled = Decision{RateScale: 1.0}

// Decide computes the enforcement decision for a client currently at score
// (0-100, threatscore.Scorer.CurrentScore). Pure function, no I/O — safe to
// call on every request.
func (p *Policy) Decide(score int) Decision {
	if p == nil {
		return unscaled
	}
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	if !cfg.Enabled {
		return unscaled
	}

	switch {
	case score >= cfg.HighRiskThreshold:
		return Decision{
			RateScale:      cfg.HighRiskRateScale,
			ForceChallenge: score >= cfg.ForceChallengeThreshold,
			Tier:           "high",
		}
	case score <= cfg.LowRiskThreshold:
		return Decision{RateScale: cfg.LowRiskRateScale, Tier: "low"}
	default:
		return unscaled
	}
}
