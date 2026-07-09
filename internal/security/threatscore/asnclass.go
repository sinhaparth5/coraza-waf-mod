package threatscore

import "strings"

// hostingASNs is a small, deliberately non-exhaustive set of well-known
// cloud/hosting/VPN-friendly autonomous systems. The bundled DB-IP ASN Lite
// database (internal/security/asn) carries only an ASN number and an
// organization name — no type/classification field — so there is no
// "is this a datacenter" signal to read directly; this is a heuristic, not
// an authoritative classification.
//
// Cloudflare's own ranges are deliberately excluded: this WAF already has a
// separate trusted-crawler/Cf-Ja4 header path for traffic that has passed
// through Cloudflare, and flagging it again here would double-count
// legitimate CDN traffic as suspicious.
var hostingASNs = map[uint]bool{
	16509:  true, // Amazon AWS
	14618:  true, // Amazon AWS
	8987:   true, // Amazon AWS EU
	15169:  true, // Google Cloud / Google LLC
	396982: true, // Google Cloud
	8075:   true, // Microsoft Azure
	8068:   true, // Microsoft Corp
	14061:  true, // DigitalOcean
	16276:  true, // OVH
	24940:  true, // Hetzner Online
	63949:  true, // Linode (Akamai)
	20473:  true, // Vultr (Choopa)
	37963:  true, // Alibaba Cloud
	45102:  true, // Alibaba Cloud (CN)
	132203: true, // Tencent Cloud
	31898:  true, // Oracle Cloud
	9009:   true, // M247 — common VPN/proxy hosting
	212238: true, // DataCamp Limited — common VPN/proxy hosting
}

// hostingKeywords catches organizations not covered by the ASN list above —
// org names vary a lot even for the same provider, so this is a coarse
// fallback, not a precise classifier.
var hostingKeywords = []string{
	"hosting", "cloud", "vpn", "datacenter", "data center", "colo", "vps",
}

// classify reports whether asn or org looks like a datacenter/hosting/VPN
// origin rather than a residential or business ISP connection.
func classify(asn uint, org string) bool {
	if hostingASNs[asn] {
		return true
	}
	lower := strings.ToLower(org)
	for _, kw := range hostingKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
