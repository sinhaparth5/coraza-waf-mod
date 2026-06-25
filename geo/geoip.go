package geo

import (
	"fmt"
	"log"
	"net"
	"sync"

	"coraza-waf-mod/storage"

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

// Check returns (blocked, reason, countryCode).
// Per-app rules take priority over global rules.
func (g *Blocker) Check(ip, appName string) (blocked bool, reason, country string) {
	country = g.LookupCountry(ip)
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
