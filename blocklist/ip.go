package blocklist

import (
	"net"
	"sync"

	"coraza-waf-mod/storage"
)

type cidrRule struct {
	network  *net.IPNet
	ruleType string
}

// IPBlocklist holds IP allow/block rules in memory for fast per-request lookup.
// Supports both plain IPs (O(1) exact match) and CIDR ranges (O(n) linear scan,
// but the CIDR list stays small in practice). Per-app rules take priority over
// global rules at each level. "allow" wins over "block" at the same scope.
// Threat-intel blocks have the lowest priority — any user rule (allow or block)
// at any scope takes precedence.
type IPBlocklist struct {
	mu          sync.RWMutex
	exact       map[string]string     // "appName:ip" or ":ip" → "block"|"allow"
	appCIDRs    map[string][]cidrRule // appName → per-app CIDR rules
	globalCIDRs []cidrRule
	// threat-intel blocks (lowest priority — user rules always win)
	intelExact map[string]struct{}
	intelCIDRs []cidrRule
}

func NewIPBlocklist(db *storage.DB) (*IPBlocklist, error) {
	bl := &IPBlocklist{}
	if err := bl.Reload(db); err != nil {
		return nil, err
	}
	if err := bl.ReloadIntel(db); err != nil {
		return nil, err
	}
	return bl, nil
}

// Reload re-reads all rules from the DB. Call after adding/removing rules via the UI.
func (bl *IPBlocklist) Reload(db *storage.DB) error {
	rows, err := db.ListIPRules()
	if err != nil {
		return err
	}

	exact := make(map[string]string, len(rows))
	appCIDRs := make(map[string][]cidrRule)
	var globalCIDRs []cidrRule

	for _, r := range rows {
		if _, network, err := net.ParseCIDR(r.IP); err == nil {
			rule := cidrRule{network: network, ruleType: r.RuleType}
			if r.AppName == "" {
				globalCIDRs = append(globalCIDRs, rule)
			} else {
				appCIDRs[r.AppName] = append(appCIDRs[r.AppName], rule)
			}
		} else {
			exact[r.AppName+":"+r.IP] = r.RuleType
		}
	}

	bl.mu.Lock()
	bl.exact = exact
	bl.appCIDRs = appCIDRs
	bl.globalCIDRs = globalCIDRs
	bl.mu.Unlock()
	return nil
}

// ReloadIntel re-reads all threat-intel IPs from the DB and swaps the
// in-memory intel block set. Called by the threatintel.Worker after each sync.
func (bl *IPBlocklist) ReloadIntel(db *storage.DB) error {
	ips, err := db.ListThreatIntelIPs()
	if err != nil {
		return err
	}
	intelExact := make(map[string]struct{}, len(ips))
	var intelCIDRs []cidrRule
	for _, ip := range ips {
		if _, network, err := net.ParseCIDR(ip); err == nil {
			intelCIDRs = append(intelCIDRs, cidrRule{network: network, ruleType: "block"})
		} else {
			intelExact[ip] = struct{}{}
		}
	}
	bl.mu.Lock()
	bl.intelExact = intelExact
	bl.intelCIDRs = intelCIDRs
	bl.mu.Unlock()
	return nil
}

// Check returns (blocked, reason). An empty reason means the request is allowed.
// Priority order: per-app exact → per-app CIDR → global exact → global CIDR →
// threat-intel (user allow rules always win over intel blocks).
func (bl *IPBlocklist) Check(ip, appName string) (blocked bool, reason string) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	parsedIP := net.ParseIP(ip)

	// Per-app exact match.
	if rt, ok := bl.exact[appName+":"+ip]; ok {
		return rt == "block", ifBlock(rt, "ip_blocked")
	}

	// Per-app CIDR match.
	if parsedIP != nil {
		for _, r := range bl.appCIDRs[appName] {
			if r.network.Contains(parsedIP) {
				return r.ruleType == "block", ifBlock(r.ruleType, "ip_blocked")
			}
		}
	}

	// Global exact match.
	if rt, ok := bl.exact[":"+ip]; ok {
		return rt == "block", ifBlock(rt, "ip_blocked_global")
	}

	// Global CIDR match.
	if parsedIP != nil {
		for _, r := range bl.globalCIDRs {
			if r.network.Contains(parsedIP) {
				return r.ruleType == "block", ifBlock(r.ruleType, "ip_blocked_global")
			}
		}
	}

	// Threat-intel block (lowest priority — user allow rules already returned above).
	if _, ok := bl.intelExact[ip]; ok {
		return true, "ip_blocked_intel"
	}
	if parsedIP != nil {
		for _, r := range bl.intelCIDRs {
			if r.network.Contains(parsedIP) {
				return true, "ip_blocked_intel"
			}
		}
	}

	return false, ""
}

func ifBlock(ruleType, reason string) string {
	if ruleType == "block" {
		return reason
	}
	return ""
}
