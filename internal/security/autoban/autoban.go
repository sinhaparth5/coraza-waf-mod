// Package autoban turns repeat offenders and severe attackers into permanent
// IP block rules. It watches the stream of logged requests (fed from the
// storage log worker via DB.SetAutobanFn), scores each blocked event per
// client IP over a sliding window, and when the configured threshold is
// crossed it writes a global block rule (visible on the IP Rules page),
// hot-reloads the in-memory blocklist, and emails the admin the reason.
//
// Scoring per event:
//
//	critical WAF rule (SQLi/RCE/XSS/LFI class)  5 points
//	any other WAF rule block                    2 points
//	rate limited                                1 point
//	bot-challenge redirect (never solved)       1 point
//
// Challenge redirects are logged with Blocked=false (a challenge is not a
// deny), but a client that keeps hitting the challenge wall without ever
// solving it is a scanner — without scoring those, a bot stuck at the
// challenge gate probes forever and is never banned. Clients that solve the
// challenge stop producing bot_challenge rows, so they accumulate nothing.
//
// Already-blocked traffic (ip_blocked*, geo_blocked*) never scores — banned
// IPs keep producing blocked log rows forever and must not re-trigger bans or
// emails. Private, loopback, and link-local addresses are never banned, and
// an existing admin rule for the IP (allow or block) always wins.
package autoban

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/internal/storage"
)

// Points per event class. The default threshold (10) means ~2 critical WAF
// hits, 4 generic WAF hits, or 10 rate-limited or challenged requests inside
// the window.
const (
	ptsCritical    = 5
	ptsWAF         = 2
	ptsRateLimited = 1
	ptsChallenged  = 1
)

// store is the slice of *storage.DB the banner needs; an interface so tests
// can run without a real database.
type store interface {
	GetAutobanConfig() (storage.AutobanConfig, error)
	GetIPRuleType(appName, ip string) (string, error)
	AddIPRuleWithNote(appName, ip, ruleType, note string) error
}

type event struct {
	t   time.Time
	pts int
	// event class for the ban-reason breakdown
	critical, waf, rl, chal bool
}

// Banner accumulates blocked-event scores per IP and issues bans.
type Banner struct {
	db     store
	reload func()                  // swaps the in-memory blocklist after a ban
	notify func(ip, reason string) // emails the ban alert (may be slow — runs async)

	mu     sync.Mutex
	cfg    storage.AutobanConfig
	hist   map[string][]event
	banned map[string]time.Time // recently banned here — suppress duplicates

	stop  chan struct{}
	once  sync.Once
	now   func() time.Time // injectable for tests
	spawn func(func())     // go func() in production; synchronous in tests
}

// New reads the current config from the DB and starts the janitor goroutine
// that keeps the per-IP history bounded. reload is called after every ban;
// notify is called asynchronously with the banned IP and the reason.
func New(db *storage.DB, reload func(), notify func(ip, reason string)) *Banner {
	b := &Banner{
		db:     db,
		reload: reload,
		notify: notify,
		hist:   make(map[string][]event),
		banned: make(map[string]time.Time),
		stop:   make(chan struct{}),
		now:    time.Now,
		spawn:  func(fn func()) { go fn() },
	}
	b.ReloadConfig()
	go b.janitor()
	return b
}

// Stop shuts down the janitor goroutine.
func (b *Banner) Stop() { b.once.Do(func() { close(b.stop) }) }

// ReloadConfig re-reads the autoban settings from the DB. Called by the UI
// save handler so changes apply without a restart.
func (b *Banner) ReloadConfig() {
	cfg, err := b.db.GetAutobanConfig()
	if err != nil {
		log.Printf("autoban: read config: %v", err)
		return
	}
	b.mu.Lock()
	b.cfg = cfg
	b.mu.Unlock()
}

// Score returns ip's current unexpired point total (0 if it has none),
// without mutating history — safe to call concurrently from other
// subsystems (e.g. the threatscore package folds this into a composite
// per-IP score). Deliberately does not reuse pruneEvents: that helper
// compacts its slice in place via evs[:0], which would corrupt b.hist[ip]'s
// backing array if called here without reassigning the result back.
func (b *Banner) Score(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := b.now().Add(-time.Duration(b.cfg.WindowMinutes) * time.Minute)
	score := 0
	for _, ev := range b.hist[ip] {
		if ev.t.After(cutoff) {
			score += ev.pts
		}
	}
	return score
}

// Record scores one logged request. It runs on the storage log worker
// goroutine, so the fast path is in-memory only; the ban itself (DB write,
// blocklist reload, email) happens on a spawned goroutine.
func (b *Banner) Record(e storage.RequestLog) {
	if e.RealIP == "" {
		return
	}
	// Challenge redirects are Blocked=false by design but still score: a
	// client repeatedly bounced to the challenge without ever solving it is
	// a scanner, not a browser.
	challenged := !e.Blocked && e.Action == "bot_challenge"
	if !e.Blocked && !challenged {
		return
	}
	// Never score traffic that is already blocked by an IP rule or geo rule:
	// re-banning adds nothing, and banned IPs log blocked rows forever.
	if strings.HasPrefix(e.Action, "ip_blocked") || strings.HasPrefix(e.Action, "geo_blocked") {
		return
	}

	ev := event{t: e.Timestamp}
	switch {
	case challenged:
		ev.pts, ev.chal = ptsChallenged, true
	case e.RuleID > 0 && criticalRule(e.RuleID):
		ev.pts, ev.critical = ptsCritical, true
	case e.RuleID > 0:
		ev.pts, ev.waf = ptsWAF, true
	case e.Action == "rate_limited":
		ev.pts, ev.rl = ptsRateLimited, true
	default:
		return
	}
	if ev.t.IsZero() {
		ev.t = b.now()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.cfg.Enabled {
		return
	}
	if !bannable(e.RealIP) {
		return
	}
	if _, dup := b.banned[e.RealIP]; dup {
		return
	}

	window := time.Duration(b.cfg.WindowMinutes) * time.Minute
	cutoff := b.now().Add(-window)
	recent := append(pruneEvents(b.hist[e.RealIP], cutoff), ev)
	b.hist[e.RealIP] = recent

	score := 0
	for _, r := range recent {
		score += r.pts
	}
	if score < b.cfg.Threshold {
		return
	}

	// Threshold crossed: mark synchronously so queued events for the same IP
	// can't trigger a second ban, then do the slow work off this goroutine.
	b.banned[e.RealIP] = b.now()
	delete(b.hist, e.RealIP)
	reason := banReason(recent, b.cfg.WindowMinutes)
	ip := e.RealIP
	b.spawn(func() { b.ban(ip, reason) })
}

// ban writes the block rule, reloads the blocklist, and sends the alert.
func (b *Banner) ban(ip, reason string) {
	// An existing rule for this IP — an admin allow (or an earlier ban that
	// survived a restart) — always wins over the automatic ban.
	if rt, err := b.db.GetIPRuleType("", ip); err != nil {
		log.Printf("autoban: rule lookup for %s: %v", ip, err)
		return
	} else if rt != "" {
		return
	}

	note := "Auto-banned — " + reason
	if err := b.db.AddIPRuleWithNote("", ip, "block", note); err != nil {
		log.Printf("autoban: ban %s: %v", ip, err)
		return
	}
	if b.reload != nil {
		b.reload()
	}
	log.Printf("autoban: banned %s (%s)", ip, reason)
	if b.notify != nil {
		b.notify(ip, reason)
	}
}

// janitor prunes stale history and old dedupe markers once a minute so the
// maps stay bounded regardless of how many IPs send blocked traffic.
func (b *Banner) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.mu.Lock()
			cutoff := b.now().Add(-time.Duration(b.cfg.WindowMinutes) * time.Minute)
			for ip, evs := range b.hist {
				if evs = pruneEvents(evs, cutoff); len(evs) == 0 {
					delete(b.hist, ip)
				} else {
					b.hist[ip] = evs
				}
			}
			// Dedupe markers only bridge the gap until the blocklist reload
			// makes the IP log as ip_blocked; an hour is more than enough.
			for ip, t := range b.banned {
				if b.now().Sub(t) > time.Hour {
					delete(b.banned, ip)
				}
			}
			b.mu.Unlock()
		case <-b.stop:
			return
		}
	}
}

func pruneEvents(evs []event, cutoff time.Time) []event {
	kept := evs[:0]
	for _, ev := range evs {
		if ev.t.After(cutoff) {
			kept = append(kept, ev)
		}
	}
	return kept
}

// criticalRule reports whether a CRS rule ID belongs to an attack-detection
// class severe enough to fast-track a ban: 930–934 (LFI/RFI/RCE/PHP/Node
// injection) and 941–944 (XSS, SQLi, session fixation, Java injection).
func criticalRule(id int) bool {
	return (id >= 930000 && id < 935000) || (id >= 941000 && id < 945000)
}

// bannable rejects addresses that must never be auto-banned: unparseable,
// loopback, RFC1918/ULA private, link-local, and unspecified addresses —
// banning those could lock out the LAN, health checks, or the admin.
func bannable(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !parsed.IsLoopback() && !parsed.IsPrivate() && !parsed.IsLinkLocalUnicast() &&
		!parsed.IsLinkLocalMulticast() && !parsed.IsUnspecified()
}

// banReason summarises what earned the ban, e.g.
// "12 flagged requests in 10 min (2 critical WAF hits, 1 WAF hit, 3 rate-limited)".
func banReason(evs []event, windowMin int) string {
	var crit, waf, rl, chal int
	for _, ev := range evs {
		switch {
		case ev.critical:
			crit++
		case ev.waf:
			waf++
		case ev.rl:
			rl++
		case ev.chal:
			chal++
		}
	}
	var parts []string
	if crit > 0 {
		parts = append(parts, fmt.Sprintf("%d critical WAF %s", crit, plural(crit, "hit")))
	}
	if waf > 0 {
		parts = append(parts, fmt.Sprintf("%d WAF %s", waf, plural(waf, "hit")))
	}
	if rl > 0 {
		parts = append(parts, fmt.Sprintf("%d rate-limited", rl))
	}
	if chal > 0 {
		parts = append(parts, fmt.Sprintf("%d unsolved bot %s", chal, plural(chal, "challenge")))
	}
	return fmt.Sprintf("%d flagged requests in %d min (%s)",
		len(evs), windowMin, strings.Join(parts, ", "))
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
