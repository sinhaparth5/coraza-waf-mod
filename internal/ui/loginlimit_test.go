package ui

import (
	"net/http/httptest"
	"testing"
	"time"
)

// fixedClock lets tests advance the limiter's notion of time.
type fixedClock struct{ t time.Time }

func (f *fixedClock) now() time.Time          { return f.t }
func (f *fixedClock) advance(d time.Duration) { f.t = f.t.Add(d) }
func newTestLimiter() (*loginLimiter, *fixedClock) {
	clock := &fixedClock{t: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)}
	l := newLoginLimiter()
	l.now = clock.now
	return l, clock
}

func TestLoginLimiterLocksAfterMaxFailures(t *testing.T) {
	l, _ := newTestLimiter()
	const ip = "203.0.113.7"

	for i := 1; i < maxLoginFailures; i++ {
		if locked := l.fail(ip); locked {
			t.Fatalf("locked after %d failures, want lock only at %d", i, maxLoginFailures)
		}
		if _, blocked := l.blocked(ip); blocked {
			t.Fatalf("blocked after %d failures, want free until lockout", i)
		}
	}
	if locked := l.fail(ip); !locked {
		t.Fatalf("failure #%d did not trigger lockout", maxLoginFailures)
	}
	wait, blocked := l.blocked(ip)
	if !blocked || wait <= 0 {
		t.Fatalf("blocked() = (%v, %v) after lockout, want positive wait", wait, blocked)
	}
}

func TestLoginLimiterUnlocksAfterLockout(t *testing.T) {
	l, clock := newTestLimiter()
	const ip = "203.0.113.7"
	for i := 0; i < maxLoginFailures; i++ {
		l.fail(ip)
	}
	clock.advance(loginLockout + time.Second)
	if _, blocked := l.blocked(ip); blocked {
		t.Fatal("still blocked after the lockout expired")
	}
}

func TestLoginLimiterWindowResets(t *testing.T) {
	l, clock := newTestLimiter()
	const ip = "203.0.113.7"
	for i := 0; i < maxLoginFailures-1; i++ {
		l.fail(ip)
	}
	// Old failures age out: a new failure after the window starts fresh.
	clock.advance(loginWindow + time.Second)
	if locked := l.fail(ip); locked {
		t.Fatal("failure after an expired window must not count toward lockout")
	}
}

func TestLoginLimiterSuccessClearsFailures(t *testing.T) {
	l, _ := newTestLimiter()
	const ip = "203.0.113.7"
	for i := 0; i < maxLoginFailures-1; i++ {
		l.fail(ip)
	}
	l.success(ip)
	if locked := l.fail(ip); locked {
		t.Fatal("failure right after a successful login must start from zero")
	}
}

func TestLoginLimiterIsolatesIPs(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < maxLoginFailures; i++ {
		l.fail("203.0.113.7")
	}
	if _, blocked := l.blocked("198.51.100.1"); blocked {
		t.Fatal("lockout for one IP must not affect another")
	}
}

func TestClientIPIgnoresSpoofedHeaders(t *testing.T) {
	h := &Handler{} // no trusted proxies configured

	req := httptest.NewRequest("POST", "/admin/login", nil)
	req.RemoteAddr = "203.0.113.7:4711"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	req.Header.Set("X-Real-IP", "10.0.0.98")

	if got := h.clientIP(req); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want socket peer 203.0.113.7 (headers must be ignored)", got)
	}
}

func TestClientIPHonorsTrustedProxy(t *testing.T) {
	h := &Handler{trustedNets: parseTrustedNets([]string{"192.0.2.0/24"})}

	req := httptest.NewRequest("POST", "/admin/login", nil)
	req.RemoteAddr = "192.0.2.10:4711"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 192.0.2.10")

	if got := h.clientIP(req); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want forwarded client 203.0.113.7", got)
	}
}
