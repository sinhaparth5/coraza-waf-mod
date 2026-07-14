package waf

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path"
	"sync"
	"time"
)

// verdictCacheTTL is intentionally short: this cache only exists to absorb
// byte-identical repeats within a single flood/scan burst (issue #13), not to
// serve a stale verdict once the request, WAF rules, or IP reputation might
// plausibly have changed.
const verdictCacheTTL = 5 * time.Second

// verdictCacheCapacity bounds memory under a large-scale/distributed flood
// where most fingerprints are unique — without a cap, the cache itself would
// become a memory-exhaustion vector rather than a mitigation for one.
const verdictCacheCapacity = 4096

// verdictEntry is the value stored per cache key.
type verdictEntry struct {
	key       string
	result    Result
	expiresAt time.Time
}

// verdictCache is a size-bounded, TTL-expiring LRU cache of WAF verdicts,
// keyed by request fingerprint (see fingerprint below). Safe for concurrent
// use.
type verdictCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	entries  map[string]*list.Element
	order    *list.List // front = most recently used
}

func newVerdictCache(ttl time.Duration, capacity int) *verdictCache {
	return &verdictCache{
		ttl:      ttl,
		capacity: capacity,
		entries:  make(map[string]*list.Element),
		order:    list.New(),
	}
}

// get returns the cached verdict for key, if present and not expired. An
// expired entry is evicted on read rather than left for a background sweep —
// this cache has no janitor goroutine, since its short TTL means expired
// entries are naturally rare and cheap to clear lazily.
func (c *verdictCache) get(key string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return Result{}, false
	}
	entry := el.Value.(*verdictEntry)
	if time.Now().After(entry.expiresAt) {
		c.order.Remove(el)
		delete(c.entries, key)
		return Result{}, false
	}
	c.order.MoveToFront(el)
	return entry.result, true
}

// put stores result under key, evicting the least-recently-used entry if the
// cache is at capacity.
func (c *verdictCache) put(key string, result Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		entry := el.Value.(*verdictEntry)
		entry.result = result
		entry.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	entry := &verdictEntry{key: key, result: result, expiresAt: time.Now().Add(c.ttl)}
	el := c.order.PushFront(entry)
	c.entries[key] = el
	if c.order.Len() > c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.entries, oldest.Value.(*verdictEntry).key)
		}
	}
}

// fingerprintEligible reports whether r is safe to key by fingerprint alone.
// A session cookie or Authorization header carries request identity that
// method+path+query+body doesn't capture — two requests with an identical
// body but different logged-in users must never share a verdict — so either
// one excludes the request from the cache entirely. This deliberately
// restricts the cache to anonymous, bot-flood-shaped traffic (issue #13).
func fingerprintEligible(r *http.Request) bool {
	return r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == ""
}

// fingerprint computes the cache key for r: method + host + normalized path
// + query + a hash of body. body is expected to be the same fully-buffered
// slice Check already read for Coraza's own inspection, so hashing it here
// costs no extra I/O.
func fingerprint(r *http.Request, body []byte) string {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	h.Write([]byte(r.Host))
	h.Write([]byte{0})
	h.Write([]byte(path.Clean(r.URL.Path)))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.RawQuery))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
