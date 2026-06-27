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
type IPBlocklist struct {
	mu          sync.RWMutex
	exact       map[string]string     // "appName:ip" or ":ip" → "block"|"allow"
	appCIDRs    map[string][]cidrRule // appName → per-app CIDR rules
	globalCIDRs []cidrRule
}

func NewIPBlocklist(db *storage.DB) (*IPBlocklist, error) {
	bl := &IPBlocklist{}
	return bl, bl.Reload(db)
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

// Check returns (blocked, reason). An empty reason means the request is allowed.
// Priority order: per-app exact → per-app CIDR → global exact → global CIDR.
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

	return false, ""
}

func ifBlock(ruleType, reason string) string {
	if ruleType == "block" {
		return reason
	}
	return ""
}
