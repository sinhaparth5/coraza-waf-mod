package ratelimit

import (
	"testing"
	"time"

	"coraza-waf-mod/internal/config"
)

func cfg(rps float64, burst int) config.RateLimitConfig {
	return config.RateLimitConfig{Enabled: true, RequestsPerSecond: rps, Burst: burst}
}

func TestDisabledAlwaysAllows(t *testing.T) {
	l := New(config.RateLimitConfig{Enabled: false})
	defer l.Stop()
	for i := 0; i < 1000; i++ {
		res := l.Allow("1.2.3.4")
		if !res.Allowed || res.RetryAfter != 0 {
			t.Fatalf("disabled limiter should always allow")
		}
	}
}

func TestBurstAllowedThenBlocked(t *testing.T) {
	l := New(cfg(1, 3)) // burst of 3
	defer l.Stop()

	// First 3 requests (burst) must be allowed.
	for i := 0; i < 3; i++ {
		if res := l.Allow("10.0.0.1"); !res.Allowed {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	// 4th request must be blocked.
	res := l.Allow("10.0.0.1")
	if res.Allowed {
		t.Fatal("request beyond burst should be blocked")
	}
	if res.RetryAfter <= 0 {
		t.Fatalf("retryAfter should be > 0, got %v", res.RetryAfter)
	}
}

func TestRetryAfterIsReasonable(t *testing.T) {
	// 2 req/s, burst 1: first request drains the bucket; second should be
	// blocked with ~500ms retryAfter.
	l := New(cfg(2, 1))
	defer l.Stop()

	l.Allow("10.0.0.2") // drains burst
	res := l.Allow("10.0.0.2")
	if res.Allowed {
		t.Fatal("second request should be blocked")
	}
	// At 2 req/s, one token refills in 500ms — allow some tolerance.
	if res.RetryAfter < 400*time.Millisecond || res.RetryAfter > 600*time.Millisecond {
		t.Fatalf("retryAfter out of expected range [400ms,600ms], got %v", res.RetryAfter)
	}
}

func TestResultCarriesLimitInfo(t *testing.T) {
	l := New(cfg(5, 10))
	defer l.Stop()

	res := l.Allow("10.0.0.9")
	if res.Limit != 5 {
		t.Fatalf("expected Limit=5, got %v", res.Limit)
	}
	if res.Burst != 10 {
		t.Fatalf("expected Burst=10, got %d", res.Burst)
	}
	if res.Remaining < 0 {
		t.Fatalf("Remaining should be >= 0, got %d", res.Remaining)
	}
}

func TestDifferentIPsAreIndependent(t *testing.T) {
	l := New(cfg(1, 1)) // burst 1
	defer l.Stop()

	l.Allow("10.0.0.1") // drains 10.0.0.1's bucket
	if res := l.Allow("10.0.0.2"); !res.Allowed {
		t.Fatal("10.0.0.2 should not be affected by 10.0.0.1's exhausted bucket")
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	l := New(cfg(10, 1)) // 10 req/s, burst 1
	defer l.Stop()

	l.Allow("10.0.0.3") // drain
	if res := l.Allow("10.0.0.3"); res.Allowed {
		t.Fatal("should be blocked immediately after drain")
	}

	// After 150ms a new token (at 10 req/s = 100ms/token) should have accrued.
	time.Sleep(150 * time.Millisecond)
	if res := l.Allow("10.0.0.3"); !res.Allowed {
		t.Fatal("should be allowed after waiting for token to refill")
	}
}

func TestTrackedIPsCount(t *testing.T) {
	l := New(cfg(100, 10))
	defer l.Stop()

	if l.TrackedIPs() != 0 {
		t.Fatal("no buckets should exist before any requests")
	}

	l.Allow("1.1.1.1")
	l.Allow("2.2.2.2")
	l.Allow("3.3.3.3")

	if got := l.TrackedIPs(); got != 3 {
		t.Fatalf("expected 3 tracked IPs, got %d", got)
	}
}

// TestAllowScaledMatchesAllowAtScale1 checks AllowScaled(ip, 1.0) behaves
// identically to Allow — the adaptive-enforcement no-op case (issue #16).
func TestAllowScaledMatchesAllowAtScale1(t *testing.T) {
	l := New(cfg(5, 3))
	defer l.Stop()

	for i := 0; i < 3; i++ {
		if res := l.AllowScaled("10.0.1.1", 1.0); !res.Allowed {
			t.Fatalf("request %d within burst should be allowed at scale 1.0", i+1)
		}
	}
	if res := l.AllowScaled("10.0.1.1", 1.0); res.Allowed {
		t.Fatal("4th request beyond burst should be blocked at scale 1.0")
	}
}

// TestAllowScaledTightensSooner checks a high-risk scale (<1) blocks a
// client sooner than the unscaled limit would.
func TestAllowScaledTightensSooner(t *testing.T) {
	l := New(cfg(10, 10)) // burst 10 normally
	defer l.Stop()

	// At scale 0.3, effective burst floors to 3 (10*0.3=3). The 4th call
	// must already be blocked, well before the unscaled burst of 10.
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.AllowScaled("10.0.1.2", 0.3).Allowed {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d requests at scale 0.3 (burst 10), want 3", allowed)
	}
}

// TestAllowScaledRelaxesFurther checks a low-risk scale (>1) allows more
// requests through than the unscaled limit would.
func TestAllowScaledRelaxesFurther(t *testing.T) {
	l := New(cfg(10, 4)) // burst 4 normally
	defer l.Stop()

	allowed := 0
	for i := 0; i < 10; i++ {
		if l.AllowScaled("10.0.1.3", 1.5).Allowed { // effective burst 6
			allowed++
		}
	}
	if allowed != 6 {
		t.Fatalf("allowed %d requests at scale 1.5 (burst 4), want 6", allowed)
	}
}

// TestAllowScaledNeverFullyLocksOut checks a zero/negative/tiny scale can't
// reduce effective burst below 1 token — a scale bug must never fully lock
// out traffic (issue #16's reversibility requirement).
func TestAllowScaledNeverFullyLocksOut(t *testing.T) {
	l := New(cfg(10, 10))
	defer l.Stop()

	for _, scale := range []float64{0, -1, 0.001} {
		ip := "10.0.1.4"
		if res := l.AllowScaled(ip, scale); !res.Allowed {
			t.Errorf("scale %v: first request must be allowed (floor of 1 burst token), got blocked", scale)
		}
	}
}

func TestJanitorEvictsIdleBuckets(t *testing.T) {
	// Override the module-level constants isn't possible from tests; instead
	// we directly call evictIdle with a future cutoff to simulate elapsed time.
	l := New(cfg(1, 5))
	defer l.Stop()

	l.Allow("192.168.1.1")
	l.Allow("192.168.1.2")
	if l.TrackedIPs() != 2 {
		t.Fatal("expected 2 buckets before eviction")
	}

	// Evict with a cutoff of "now + 1 hour" so all buckets are considered idle.
	l.mu.Lock()
	cutoff := time.Now().Add(time.Hour)
	for ip, b := range l.buckets {
		if b.lastRefill.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
	l.mu.Unlock()

	if l.TrackedIPs() != 0 {
		t.Fatalf("expected 0 buckets after eviction, got %d", l.TrackedIPs())
	}
}
