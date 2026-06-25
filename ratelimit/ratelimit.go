// Package ratelimit implements a per-IP token-bucket limiter, applied
// globally across all apps as a cheap anti-flood check ahead of geo/WAF
// inspection. This is the in-process placeholder noted in PROGRESS.md
// Phase 6 — Phase 8 supersedes it with a Redis-backed limiter scoped to
// specific routes (login endpoints, heavy DB-backed routes) once multiple
// instances need to share limiter state.
package ratelimit

import (
	"sync"
	"time"

	"coraza-waf-mod/config"
)

// janitorInterval/idleTTL bound memory from per-IP buckets: a public-facing
// proxy sees an unbounded number of distinct client IPs over time, unlike
// the rule-count-bounded maps in blocklist/geo, so idle buckets must be
// evicted instead of kept forever.
const (
	janitorInterval = time.Minute
	idleTTL         = 5 * time.Minute
)

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// Limiter enforces a requests-per-second rate with burst capacity, per
// client IP. The zero value (via New with Enabled: false) always allows.
type Limiter struct {
	enabled bool
	rate    float64 // tokens added per second
	burst   float64 // max tokens a bucket can hold

	mu      sync.Mutex
	buckets map[string]*bucket

	stop chan struct{}
}

// New builds a Limiter from config. When cfg.Enabled is false, Allow always
// returns true and no janitor goroutine is started.
func New(cfg config.RateLimitConfig) *Limiter {
	l := &Limiter{
		enabled: cfg.Enabled,
		rate:    cfg.RequestsPerSecond,
		burst:   float64(cfg.Burst),
		buckets: make(map[string]*bucket),
	}
	if l.enabled {
		l.stop = make(chan struct{})
		go l.runJanitor()
	}
	return l
}

// Allow reports whether a request from ip may proceed, consuming one token.
// When blocked, retryAfter is the time until the bucket refills enough for
// the next token; when allowed, it is zero.
func (l *Limiter) Allow(ip string) (allowed bool, retryAfter time.Duration) {
	if !l.enabled {
		return true, 0
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: l.burst - 1, lastRefill: now}
		l.buckets[ip] = b
		return true, 0
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastRefill = now

	if b.tokens < 1 {
		waitSecs := (1 - b.tokens) / l.rate
		return false, time.Duration(waitSecs * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// TrackedIPs returns the number of per-IP buckets currently in memory.
func (l *Limiter) TrackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Stop terminates the janitor goroutine. Safe to call on a disabled Limiter.
func (l *Limiter) Stop() {
	if l.stop != nil {
		close(l.stop)
	}
}

func (l *Limiter) runJanitor() {
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.evictIdle()
		case <-l.stop:
			return
		}
	}
}

func (l *Limiter) evictIdle() {
	cutoff := time.Now().Add(-idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}
