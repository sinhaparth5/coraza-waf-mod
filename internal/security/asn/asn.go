// Package asn provides fast, offline IP-to-ASN lookups using the bundled
// DB-IP Lite ASN database (CC BY 4.0 — see THIRD_PARTY_NOTICES.md).
package asn

import (
	"fmt"
	"log"
	"net"

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

// Close releases the memory-mapped database file.
func (l *Lookup) Close() error {
	if l != nil && l.reader != nil {
		return l.reader.Close()
	}
	return nil
}
