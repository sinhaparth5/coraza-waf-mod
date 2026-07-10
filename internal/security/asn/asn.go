// Package asn provides fast, offline IP-to-ASN lookups using the bundled
// DB-IP Lite ASN database (CC BY 4.0 — see THIRD_PARTY_NOTICES.md).
package asn

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// Lookup wraps a MaxMind-compatible ASN database reader.
type Lookup struct {
	reader *geoip2.Reader
}

// New opens the bundled DB-IP Lite ASN database.
func New() (*Lookup, error) {
	data, err := embeddedFS.ReadFile("dbip-asn-lite.mmdb")
	if err != nil {
		return nil, fmt.Errorf("asn: read bundled DB: %w", err)
	}
	r, err := geoip2.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("asn: open bundled DB: %w", err)
	}
	log.Printf("asn: loaded DB-IP Lite ASN database")
	return &Lookup{reader: r}, nil
}

// Lookup returns the autonomous system number and organization name for ip.
// Returns (0, "") on any error or unknown IP.
func (l *Lookup) Lookup(ipStr string) (asnNum uint, org string) {
	if l == nil || l.reader == nil {
		return 0, ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, ""
	}
	rec, err := l.reader.ASN(ip)
	if err != nil || rec == nil {
		return 0, ""
	}
	return uint(rec.AutonomousSystemNumber), rec.AutonomousSystemOrganization
}

// connCacheTTL bounds how long a per-connection ASN lookup is reused. See
// geo.connCacheTTL's doc comment — same reasoning applies here: TLS
// connections are cleaned up immediately via DeleteConn (wired into the
// ConnState hook in main.go alongside ja3/ja4), this TTL reclaims entries
// for plain HTTP connections, which have no such hook.
const connCacheTTL = 10 * time.Minute

// cacheEntry pairs a cached ASN/org result with the client IP it was computed
// for, re-checked on every read so a reverse proxy that multiplexes several
// real clients over one keep-alive connection to this origin (e.g.
// Cloudflare's connection pool) can't leak one client's ASN onto another's
// request sharing the same remoteAddr.
type cacheEntry struct {
	ip        string
	asnNum    uint
	org       string
	expiresAt time.Time
}

// connCache maps a connection's remote address to its last ASN lookup, the
// same per-connection sync.Map pattern ja3/ja4 use for their fingerprint
// stores — populated lazily on first lookup (unlike ja3/ja4, which populate
// eagerly at TLS handshake time, since an ASN lookup needs the resolved
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
			if now.After(v.(cacheEntry).expiresAt) {
				connCache.Delete(k)
			}
			return true
		})
	}
}

// DeleteConn removes any cached ASN lookup for remoteAddr. Call when the
// connection closes, mirroring ja3pkg.Delete/ja4pkg.Delete.
func DeleteConn(remoteAddr string) {
	connCache.Delete(remoteAddr)
}

// LookupForConn returns the ASN/org for ipStr, reusing the entry cached for
// remoteAddr when it's still fresh and was computed for this same ipStr.
// remoteAddr is the request's underlying TCP connection address
// (r.RemoteAddr), used only to key the cache — the result itself is always
// looked up for ipStr.
func (l *Lookup) LookupForConn(remoteAddr, ipStr string) (asnNum uint, org string) {
	if l == nil {
		return 0, ""
	}
	if v, ok := connCache.Load(remoteAddr); ok {
		e := v.(cacheEntry)
		if e.ip == ipStr && time.Now().Before(e.expiresAt) {
			return e.asnNum, e.org
		}
	}
	asnNum, org = l.Lookup(ipStr)
	connCache.Store(remoteAddr, cacheEntry{ip: ipStr, asnNum: asnNum, org: org, expiresAt: time.Now().Add(connCacheTTL)})
	return asnNum, org
}

// Close releases the memory-mapped database file.
func (l *Lookup) Close() error {
	if l != nil && l.reader != nil {
		return l.reader.Close()
	}
	return nil
}
