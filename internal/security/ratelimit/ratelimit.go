// Package ratelimit implements per-IP token-bucket limiting with two backends:
//   - Limiter: in-process memory with optional SQLite write-back persistence
//     (survives restarts, single-node only)
//   - RedisBackend: Redis-backed token bucket for multi-node deployments
//
// Both satisfy the Backend interface so callers don't need to know which is
// in use. The global limiter in main.go uses whichever is configured; per-service
// limiters always use the in-process Limiter (they don't need distribution).
package ratelimit

import (
	"sync"
	"time"

	"coraza-waf-mod/internal/config"
)

// Backend is the common interface for the global rate limiter. Both the
// in-process Limiter and RedisBackend satisfy it.
type Backend interface {
	Allow(ip string) Result
	// AllowScaled behaves like Allow but with rate and burst multiplied by
	// scale (1.0 = identical to Allow). Used by threat-score-driven adaptive
	// enforcement (issue #16) to tighten or relax the limit for a specific
	// client without touching the global config. scale <= 0 is treated as
	// 1.0 — a bad scale must never fully lock out traffic.
	AllowScaled(ip string, scale float64) Result
	TrackedIPs() int
	Stop()
}

// BucketState is a serialisable snapshot of a single IP's token bucket,
// used by SQLite persistence.
type BucketState struct {
	IP         string
	Tokens     float64
	LastRefill time.Time
}

// StateStore is implemented by storage.DB and passed to StartPersistence.
// Defined here (not in storage/) to avoid an import cycle.
type StateStore interface {
	SaveRateLimitState(states []BucketState) error
	LoadRateLimitState() ([]BucketState, error)
	PurgeRateLimitState(before time.Time) error
}

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

	stop     chan struct{}
	stopOnce sync.Once
}

// NewWithParams builds an always-enabled Limiter directly from RPS and burst
// values, for use by per-service limiters that don't come from config.yaml.
func NewWithParams(rps float64, burst int) *Limiter {
	l := &Limiter{
		enabled: true,
		rate:    rps,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
	}
	go l.runJanitor()
	return l
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

// Result is the outcome of a single Allow call.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration // duration until the next token refills; >0 only when !Allowed
	Remaining  int           // floor of tokens remaining after this request; 0 when blocked
	Limit      float64       // configured RPS (0 means limiter is disabled / no limit)
	Burst      int           // configured burst capacity
}

// Allow reports whether a request from ip may proceed, consuming one token.
func (l *Limiter) Allow(ip string) Result {
	return l.allow(ip, l.rate, l.burst)
}

// AllowScaled behaves like Allow but against rate/burst multiplied by scale.
// Satisfies Backend. Recomputing the effective rate/burst on every call is
// correct token-bucket math even when scale changes between calls for the
// same IP — the bucket itself (tokens/lastRefill) doesn't need to know about
// scaling at all.
func (l *Limiter) AllowScaled(ip string, scale float64) Result {
	if scale <= 0 {
		scale = 1.0
	}
	burst := l.burst * scale
	if burst < 1 {
		burst = 1 // a scale bug must never fully lock out traffic
	}
	return l.allow(ip, l.rate*scale, burst)
}

func (l *Limiter) allow(ip string, rate, burst float64) Result {
	if !l.enabled {
		return Result{Allowed: true}
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: burst - 1, lastRefill: now}
		l.buckets[ip] = b
		return Result{Allowed: true, Remaining: int(b.tokens), Limit: rate, Burst: int(burst)}
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastRefill = now

	if b.tokens < 1 {
		waitSecs := (1 - b.tokens) / rate
		return Result{
			Allowed:    false,
			RetryAfter: time.Duration(waitSecs * float64(time.Second)),
			Remaining:  0,
			Limit:      rate,
			Burst:      int(burst),
		}
	}
	b.tokens--
	return Result{Allowed: true, Remaining: int(b.tokens), Limit: rate, Burst: int(burst)}
}

// TrackedIPs returns the number of per-IP buckets currently in memory.
func (l *Limiter) TrackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Stop terminates the janitor goroutine. Safe to call on a disabled Limiter,
// and safe to call more than once — a backend can be stopped by a hot reload
// and again during shutdown, so double-stopping must not panic.
func (l *Limiter) Stop() {
	if l.stop != nil {
		l.stopOnce.Do(func() { close(l.stop) })
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

// Snapshot returns a copy of all current bucket states for persistence.
func (l *Limiter) Snapshot() []BucketState {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BucketState, 0, len(l.buckets))
	for ip, b := range l.buckets {
		out = append(out, BucketState{IP: ip, Tokens: b.tokens, LastRefill: b.lastRefill})
	}
	return out
}

// RestoreFrom loads previously-persisted bucket states, skipping any entry
// that has already idled out.
func (l *Limiter) RestoreFrom(states []BucketState) {
	cutoff := time.Now().Add(-idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range states {
		if s.LastRefill.After(cutoff) {
			l.buckets[s.IP] = &bucket{tokens: s.Tokens, lastRefill: s.LastRefill}
		}
	}
}

// StartPersistence launches a goroutine that saves bucket state to store
// every saveInterval and purges entries older than idleTTL from the DB.
// Call this once after the Limiter is created and state has been restored.
func (l *Limiter) StartPersistence(store StateStore) {
	if !l.enabled || store == nil {
		return
	}
	const saveInterval = 10 * time.Second
	go func() {
		t := time.NewTicker(saveInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = store.SaveRateLimitState(l.Snapshot())
				_ = store.PurgeRateLimitState(time.Now().Add(-idleTTL))
			case <-l.stop:
				// Final save on shutdown so the next startup has fresh state.
				_ = store.SaveRateLimitState(l.Snapshot())
				return
			}
		}
	}()
}
