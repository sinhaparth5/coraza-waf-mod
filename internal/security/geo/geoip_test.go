package geo

import (
	"path/filepath"
	"testing"

	"coraza-waf-mod/internal/storage"
)

// newTestBlocker returns a Blocker backed by the bundled GeoLite2 DB with no
// geo rules loaded, backed by a throwaway SQLite DB just to satisfy Reload.
func newTestBlocker(t *testing.T) *Blocker {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "geo-test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	g, err := New("", db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestLookupCountryCachedReusesConnCache(t *testing.T) {
	g := newTestBlocker(t)
	const remoteAddr = "203.0.113.1:12345"
	const ip = "8.8.8.8"

	want := g.LookupCountry(ip)
	if want == "" {
		t.Fatal("expected a non-empty country for 8.8.8.8 from the bundled GeoLite2 DB")
	}

	if got := g.lookupCountryCached(remoteAddr, ip); got != want {
		t.Fatalf("first cached lookup = %q, want %q", got, want)
	}

	// Break the underlying reader so a real (uncached) lookup would return
	// "". A second call still returning `want` proves the cache was used
	// instead of falling through to the broken reader.
	g.reader = nil
	if got := g.lookupCountryCached(remoteAddr, ip); got != want {
		t.Fatalf("cached lookup after reader broke = %q, want %q (cache was not reused)", got, want)
	}
}

func TestLookupCountryCachedInvalidatesOnIPChange(t *testing.T) {
	g := newTestBlocker(t)
	const remoteAddr = "203.0.113.2:12345"

	if got := g.lookupCountryCached(remoteAddr, "8.8.8.8"); got == "" {
		t.Fatal("expected a non-empty country for 8.8.8.8")
	}

	// Same remoteAddr (simulating a proxy connection reused for a different
	// real client), different IP: must not return 8.8.8.8's cached country.
	g.reader = nil
	if got := g.lookupCountryCached(remoteAddr, "9.9.9.9"); got != "" {
		t.Fatalf("lookup for a different IP on the same remoteAddr returned %q, want \"\" (stale cache entry leaked across clients)", got)
	}
}

func TestDeleteConnClearsCache(t *testing.T) {
	g := newTestBlocker(t)
	const remoteAddr = "203.0.113.3:12345"
	const ip = "8.8.8.8"

	if got := g.lookupCountryCached(remoteAddr, ip); got == "" {
		t.Fatal("expected a non-empty country for 8.8.8.8")
	}

	DeleteConn(remoteAddr)
	g.reader = nil
	if got := g.lookupCountryCached(remoteAddr, ip); got != "" {
		t.Fatalf("lookup after DeleteConn = %q, want \"\" (entry should have been evicted, forcing a fresh — and here broken — lookup)", got)
	}
}

func TestCheckUsesRemoteAddrCache(t *testing.T) {
	g := newTestBlocker(t)
	g.rules = map[string]string{":US": "block"}
	const remoteAddr = "203.0.113.4:12345"

	// Country lookups for 8.8.8.8 (Google, US) should be consistent across
	// both calls Handle() makes per request (logging + block decision).
	blocked1, _, country1 := g.Check(remoteAddr, "8.8.8.8", "")
	blocked2, _, country2 := g.Check(remoteAddr, "8.8.8.8", "")
	if country1 == "" || country1 != country2 {
		t.Fatalf("country mismatch across calls: %q vs %q", country1, country2)
	}
	if blocked1 != blocked2 {
		t.Fatalf("blocked mismatch across calls: %v vs %v", blocked1, blocked2)
	}
}
