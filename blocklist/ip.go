package blocklist

import (
	"sync"

	"coraza-waf-mod/storage"
)

// IPBlocklist holds IP allow/block rules in memory for O(1) per-request lookup.
// Per-app rules take priority over global rules.
// "allow" always wins over "block" at the same scope.
type IPBlocklist struct {
	mu    sync.RWMutex
	rules map[string]string // key: "appName:ip" or ":ip" (global) → "block"|"allow"
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

	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r.AppName+":"+r.IP] = r.RuleType
	}

	bl.mu.Lock()
	bl.rules = m
	bl.mu.Unlock()
	return nil
}

// Check returns (blocked, reason). An empty reason means the request is allowed.
func (bl *IPBlocklist) Check(ip, appName string) (blocked bool, reason string) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Per-app rule is most specific — check first.
	if rt, ok := bl.rules[appName+":"+ip]; ok {
		if rt == "block" {
			return true, "ip_blocked"
		}
		return false, "" // explicitly allowed for this app
	}

	// Fall back to global rule.
	if rt, ok := bl.rules[":"+ip]; ok {
		if rt == "block" {
			return true, "ip_blocked_global"
		}
		return false, "" // globally allowed
	}

	return false, ""
}
