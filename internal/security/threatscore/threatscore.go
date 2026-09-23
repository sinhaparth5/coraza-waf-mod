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
// Record also caches the score it just computed in memory, read back
// synchronously via CurrentScore — used by threat-score-driven adaptive
// enforcement (issue #16) to make a per-request decision without a SQLite
// read on the hot path (mirroring blocklist/geo's in-memory-cache model,
// not adding a new query-per-request pattern). Because Record runs
// asynchronously after the request that produced it has already been
// logged, CurrentScore for a given IP always reflects that IP's *previous*
// requests, never the one currently in flight — the same one-request lag
// autoban's ban already has.
//
// Scoring per event (each component capped, total capped at 100):
//
//	autoban's current point total for the IP   up to 40
//	bot.Analyze score already on the log entry up to 20
//	ASN/org looks like hosting/VPN (asnclass.go) flat 15
//	country has an admin-configured geo block rule flat 10
//	JA4 fingerprint's lifetime blocked-hit count up to 15
//
// The ASN/org component's heuristic can optionally be refined by TypeSafe
// (typesafeclassify.go, Settings page's "AI classification" card): a
// never-before-seen ASN is judged once, off the log-worker goroutine, and
// cached forever after. Disabled by default — see classifyASN.
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

// janitorInterval/idleTTL bound the in-memory score cache — a public-facing
// proxy sees an unbounded number of distinct client IPs over time, same
// reasoning as ratelimit.Limiter's bucket map. idleTTL is much longer than
// ratelimit's (5m): a threat score is meant to reflect standing reputation,
// not a short-lived rate-limit window, and letting it decay too fast would
// mean a brief lull in traffic silently resets a high-risk IP back to 0.
const (
	janitorInterval = time.Minute
	idleTTL         = 30 * time.Minute
)

// store is the subset of *storage.DB the scorer needs — an interface so
// tests can run against a fake without a real database.
type store interface {
	UpsertIPThreatScore(storage.IPThreatScore) error
	BumpJA4Reputation(ja4 string, blocked bool) (hits, blockedHits int, err error)
	InsertTypeSafeCall(storage.TypeSafeCall) error
}

// Scorer accumulates the composite per-IP threat score.
type Scorer struct {
	db           store
	autobanScore func(ip string) int

	mu            sync.RWMutex
	riskCountries map[string]bool
	scores        map[string]int       // in-memory cache backing CurrentScore
	lastSeen      map[string]time.Time // bounds the scores map, mirrors ratelimit.Limiter's bucket janitor

	// classifier is nil when TypeSafe-backed ASN classification is off
	// (the default) — classifyASN then falls back to asnclass.go's
	// heuristic alone. asnCache/asnInFlight cache judgments per ASN, since
	// an ASN's organization doesn't change request-to-request: see
	// classifyASN.
	classifier  hostingClassifier
	asnCache    map[uint]bool
	asnInFlight map[uint]bool

	stop chan struct{}
	once sync.Once

	now func() time.Time // injectable for tests
}

// New builds a Scorer and starts its janitor goroutine. autobanScore is
// typically (*autoban.Banner).Score — injected rather than imported
// directly so this package doesn't need to know how autoban stores its
// history, only that it can report a current point total for an IP.
func New(db *storage.DB, autobanScore func(ip string) int) *Scorer {
	s := &Scorer{
		db:            db,
		autobanScore:  autobanScore,
		riskCountries: make(map[string]bool),
		scores:        make(map[string]int),
		lastSeen:      make(map[string]time.Time),
		asnCache:      make(map[uint]bool),
		asnInFlight:   make(map[uint]bool),
		stop:          make(chan struct{}),
		now:           time.Now,
	}
	go s.janitor()
	return s
}

// Stop terminates the janitor goroutine. Safe to call more than once.
func (s *Scorer) Stop() { s.once.Do(func() { close(s.stop) }) }

// CurrentScore returns ip's most recently computed composite score, or 0 if
// Record has never processed a request from ip (or its cache entry has
// idled out). Safe to call from the request hot path — pure in-memory read,
// no SQLite. See the package doc comment for the one-request lag this
// implies.
func (s *Scorer) CurrentScore(ip string) int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scores[ip]
}

func (s *Scorer) janitor() {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := s.now().Add(-idleTTL)
			s.mu.Lock()
			for ip, t := range s.lastSeen {
				if t.Before(cutoff) {
					delete(s.lastSeen, ip)
					delete(s.scores, ip)
				}
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
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

// ReloadTypeSafeConfig enables or disables TypeSafe-backed ASN classification
// and clears the ASN cache, so a key change or a disable takes effect on the
// next request rather than serving stale judgments made under the old
// config. Call after every Settings save, the same way ReloadGeoRules is
// called after every geo-rule change.
func (s *Scorer) ReloadTypeSafeConfig(enabled bool, apiKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled && apiKey != "" {
		s.classifier = newTypeSafeClient(apiKey)
	} else {
		s.classifier = nil
	}
	s.asnCache = make(map[uint]bool)
	s.asnInFlight = make(map[uint]bool)
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
	if s.classifyASN(e.ASN, e.Org) {
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

	// Update the in-memory cache regardless of whether the DB write below
	// succeeds — CurrentScore should reflect the freshest computed value for
	// live enforcement decisions even if SQLite hiccups.
	s.mu.Lock()
	s.scores[e.RealIP] = total
	s.lastSeen[e.RealIP] = s.now()
	s.mu.Unlock()

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

// classifyASN reports whether asn/org looks like hosting/VPN infrastructure.
// With TypeSafe enabled, a never-before-seen ASN is judged once via a
// background goroutine and cached forever after — an ASN's organization
// doesn't change request-to-request. Every call, including the one that
// triggers that judgment, returns the fast hardcoded heuristic immediately:
// Record runs on the log-worker goroutine and must never block on network
// I/O (see the package doc comment).
func (s *Scorer) classifyASN(asn uint, org string) bool {
	s.mu.RLock()
	classifier := s.classifier
	cached, ok := s.asnCache[asn]
	inFlight := s.asnInFlight[asn]
	s.mu.RUnlock()

	if classifier == nil {
		return classify(asn, org)
	}
	if ok {
		return cached
	}
	if !inFlight && org != "" {
		s.mu.Lock()
		s.asnInFlight[asn] = true
		s.mu.Unlock()
		go s.judgeASN(classifier, asn, org)
	}
	return classify(asn, org)
}

func (s *Scorer) judgeASN(c hostingClassifier, asn uint, org string) {
	defer func() {
		s.mu.Lock()
		delete(s.asnInFlight, asn)
		s.mu.Unlock()
	}()
	start := s.now()
	judgment, err := c.judgeHosting(org)
	duration := s.now().Sub(start)

	call := storage.TypeSafeCall{
		Ts:           start,
		ASN:          asn,
		Org:          org,
		Hosting:      judgment.Hosting,
		InputTokens:  judgment.InputTokens,
		OutputTokens: judgment.OutputTokens,
		DurationMs:   duration.Milliseconds(),
	}
	if err != nil {
		call.Error = err.Error()
	}
	if logErr := s.db.InsertTypeSafeCall(call); logErr != nil {
		log.Printf("threatscore: log typesafe call for ASN %d: %v", asn, logErr)
	}

	if err != nil {
		log.Printf("threatscore: typesafe classify ASN %d (%q): %v", asn, org, err)
		return // uncached; the heuristic keeps being used, and this retries next time
	}
	s.mu.Lock()
	s.asnCache[asn] = judgment.Hosting
	s.mu.Unlock()
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
