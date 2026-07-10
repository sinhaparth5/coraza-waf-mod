package geo

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"coraza-waf-mod/internal/storage"

	"github.com/oschwald/geoip2-golang"
)

// Blocker wraps a MaxMind GeoLite2 reader and geo block/allow rules.
type Blocker struct {
	reader *geoip2.Reader
	mu     sync.RWMutex
	rules  map[string]string // key: "appName:CC" or ":CC" (global) → "block"|"allow"
}

// New opens the configured MaxMind .mmdb file and loads geo rules from the DB.
// If dbPath is empty, it falls back to the bundled GeoLite2 Country database.
func New(dbPath string, db *storage.DB) (*Blocker, error) {
	g := &Blocker{}

	if dbPath != "" {
		reader, err := geoip2.Open(dbPath)
		if err != nil {
			return nil, fmt.Errorf("geoip open %q: %w", dbPath, err)
		}
		g.reader = reader
		log.Printf("geo: loaded MaxMind DB from %s", dbPath)
	} else {
		data, err := embeddedFS.ReadFile("GeoLite2-Country.mmdb")
		if err != nil {
			return nil, fmt.Errorf("geoip read bundled GeoLite2-Country.mmdb: %w", err)
		}
		reader, err := geoip2.FromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("geoip open bundled GeoLite2-Country.mmdb: %w", err)
		}
		g.reader = reader
		log.Printf("geo: loaded bundled MaxMind GeoLite2-Country.mmdb")
	}

	return g, g.Reload(db)
}

// Reload re-reads geo rules from the DB. Call after rules change.
func (g *Blocker) Reload(db *storage.DB) error {
	rows, err := db.ListGeoRules()
	if err != nil {
		return err
	}

	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r.AppName+":"+r.CountryCode] = r.RuleType
	}

	g.mu.Lock()
	g.rules = m
	g.mu.Unlock()
	return nil
}

func (g *Blocker) Close() error {
	if g.reader != nil {
		return g.reader.Close()
	}
	return nil
}

// LookupCountry returns the ISO 3166-1 alpha-2 country code for the given IP.
// Returns "" if the reader is not loaded or the IP is unknown.
func (g *Blocker) LookupCountry(ipStr string) string {
	if g.reader == nil {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	record, err := g.reader.Country(ip)
	if err != nil || record == nil {
		return ""
	}
	return record.Country.IsoCode
}

// connCacheTTL bounds how long a per-connection country lookup is reused.
// TLS connections are cleaned up immediately when they close (DeleteConn is
// wired into the same ConnState hook that already cleans up ja3/ja4 in
// main.go); this TTL is the safety net for plain HTTP connections, which have
// no such hook, so their entries still get reclaimed by the janitor below
// instead of accumulating forever.
const connCacheTTL = 10 * time.Minute

// countryCacheEntry pairs a cached country with the client IP it was computed
// for. The IP is re-checked on every read: a reverse proxy that multiplexes
// several real clients over one keep-alive connection to this origin (e.g.
// Cloudflare's connection pool) would otherwise let one client's country
// leak onto another's request sharing the same remoteAddr.
type countryCacheEntry struct {
	ip        string
	country   string
	expiresAt time.Time
}

// connCache maps a connection's remote address to its last country lookup,
// the same per-connection sync.Map pattern ja3/ja4 use for their fingerprint
// stores — populated lazily on first lookup (unlike ja3/ja4, which populate
// eagerly at TLS handshake time, since a country lookup needs the resolved
// client IP, which isn't known until the request arrives).
var connCache sync.Map

func init() {
	go janitor()
}

// janitor sweeps expired entries periodically, bounding connCache's size for
// connections DeleteConn is never called on (plain HTTP has no ConnState hook).
func janitor() {
	t := time.NewTicker(connCacheTTL / 2)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		connCache.Range(func(k, v any) bool {
			if now.After(v.(countryCacheEntry).expiresAt) {
				connCache.Delete(k)
			}
			return true
		})
	}
}

// DeleteConn removes any cached country lookup for remoteAddr. Call when the
// connection closes, mirroring ja3pkg.Delete/ja4pkg.Delete.
func DeleteConn(remoteAddr string) {
	connCache.Delete(remoteAddr)
}

// lookupCountryCached returns the country for ip, reusing the entry cached
// for remoteAddr when it's still fresh and was computed for this same ip.
func (g *Blocker) lookupCountryCached(remoteAddr, ip string) string {
	if v, ok := connCache.Load(remoteAddr); ok {
		e := v.(countryCacheEntry)
		if e.ip == ip && time.Now().Before(e.expiresAt) {
			return e.country
		}
	}
	country := g.LookupCountry(ip)
	connCache.Store(remoteAddr, countryCacheEntry{ip: ip, country: country, expiresAt: time.Now().Add(connCacheTTL)})
	return country
}

// Check returns (blocked, reason, countryCode). remoteAddr is the request's
// underlying TCP connection address (r.RemoteAddr), used only to key the
// per-connection country cache above — the block decision itself is always
// based on ip. Per-app rules take priority over global rules.
func (g *Blocker) Check(remoteAddr, ip, appName string) (blocked bool, reason, country string) {
	country = g.lookupCountryCached(remoteAddr, ip)
	if country == "" {
		return false, "", ""
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Per-app rule is most specific.
	if rt, ok := g.rules[appName+":"+country]; ok {
		if rt == "block" {
			return true, "geo_blocked:" + country, country
		}
		return false, "", country
	}

	// Global rule.
	if rt, ok := g.rules[":"+country]; ok {
		if rt == "block" {
			return true, "geo_blocked_global:" + country, country
		}
		return false, "", country
	}

	return false, "", country
}
