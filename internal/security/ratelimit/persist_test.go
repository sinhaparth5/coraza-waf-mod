package ratelimit

import (
	"os"
	"sync"
	"testing"
	"time"

	"palisade/internal/config"
)

type fakeStore struct {
	mu    sync.Mutex
	saved [][]BucketState
}

func (f *fakeStore) SaveRateLimitState(s []BucketState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = append(f.saved, s)
	return nil
}
func (f *fakeStore) LoadRateLimitState() ([]BucketState, error) { return nil, nil }
func (f *fakeStore) PurgeRateLimitState(time.Time) error        { return nil }

func TestSnapshotRestoreAndEvict(t *testing.T) {
	l := NewWithParams(1, 5)
	defer l.Stop()
	l.Allow("10.0.0.1")

	snap := l.Snapshot()
	if len(snap) != 1 || snap[0].IP != "10.0.0.1" || snap[0].Tokens != 4 {
		t.Fatalf("Snapshot = %+v", snap)
	}

	fresh := NewWithParams(1, 5)
	defer fresh.Stop()
	fresh.RestoreFrom(append(snap, BucketState{IP: "stale", Tokens: 1, LastRefill: time.Now().Add(-2 * idleTTL)}))
	if fresh.TrackedIPs() != 1 {
		t.Fatalf("RestoreFrom kept %d buckets, want 1 (stale entry dropped)", fresh.TrackedIPs())
	}

	fresh.mu.Lock()
	fresh.buckets["10.0.0.1"].lastRefill = time.Now().Add(-2 * idleTTL)
	fresh.mu.Unlock()
	fresh.evictIdle()
	if fresh.TrackedIPs() != 0 {
		t.Fatal("evictIdle kept an idle bucket")
	}
}

func TestStartPersistenceSavesOnStop(t *testing.T) {
	store := &fakeStore{}
	New(cfg(1, 1)).StartPersistence(nil)                  // nil store: no-op
	New(config.RateLimitConfig{}).StartPersistence(store) // disabled: no-op

	l := New(cfg(1, 5))
	l.Allow("10.0.0.2")
	l.StartPersistence(store)
	l.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		n := len(store.saved)
		store.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("final save on Stop never happened")
}

func TestRedisBackendUnreachable(t *testing.T) {
	if _, err := NewRedisBackend("", "", 1, 1); err == nil {
		t.Error("empty addr should error")
	}
	if _, err := NewRedisBackend("127.0.0.1:1", "", 1, 1); err == nil {
		t.Error("unreachable addr should error")
	}
	if err := PingRedis("127.0.0.1:1", ""); err == nil {
		t.Error("PingRedis to unreachable addr should error")
	}
}

// TestRedisBackend needs a real Redis; CI provides one via TEST_REDIS_ADDR.
func TestRedisBackend(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	if err := PingRedis(addr, ""); err != nil {
		t.Fatal(err)
	}
	r, err := NewRedisBackend(addr, "", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if err := r.Ping(); err != nil {
		t.Fatal(err)
	}

	ip := "redis-test-" + time.Now().Format("150405.000000000")
	for i := range 2 {
		if !r.Allow(ip).Allowed {
			t.Fatalf("request %d within burst of 2 should be allowed", i+1)
		}
	}
	res := r.Allow(ip)
	if res.Allowed || res.RetryAfter <= 0 {
		t.Fatalf("third request should be blocked: %+v", res)
	}
	if res := r.AllowScaled(ip+"-scaled", 0); !res.Allowed || res.Burst != 2 {
		t.Fatalf("scale<=0 must behave like 1.0: %+v", res)
	}
	if res := r.AllowScaled(ip+"-tiny", 0.01); !res.Allowed || res.Burst != 1 {
		t.Fatalf("tiny scale must floor burst at 1: %+v", res)
	}
	if r.TrackedIPs() < 1 {
		t.Error("TrackedIPs should count stored keys")
	}

	// A dead connection fails open.
	r.Stop()
	if !r.Allow(ip).Allowed {
		t.Error("closed client should fail open")
	}
}
