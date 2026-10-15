package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"palisade/internal/config"
	"palisade/internal/security/waf"
	"palisade/internal/storage"
)

// TestCustomRuleDirectives is issue #112's "done when" at the engine level:
// a saved global rule blocks, a service-scoped one only lands in that
// service's directives, and a disabled or invalid row is left out.
func TestCustomRuleDirectives(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, r := range []storage.WAFCustomRule{
		{Rule: `SecRule ARGS "@contains evil" "id:1000001,phase:1,deny,status:403"`, Enabled: true},
		{Rule: `SecRule ARGS "@contains shoponly" "id:1000002,phase:1,deny,status:403"`, ServiceName: "shop", Enabled: true},
		{Rule: `SecRule ARGS "@contains off" "id:1000003,phase:1,deny,status:403"`},
		{Rule: `SecRuleEngine Off`, Enabled: true},
	} {
		if err := db.SaveWAFCustomRule(r); err != nil {
			t.Fatal(err)
		}
	}
	rules, _ := db.ListWAFCustomRules()
	global, bySvc := customRuleDirectives(rules)
	if len(bySvc) != 1 || bySvc["shop"] == "" {
		t.Fatalf("byService = %v", bySvc)
	}

	eng, err := waf.NewWithDirectives(config.Defaults().WAF, nil, global)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query string
		block bool
	}{
		{"q=evil", true},
		{"q=shoponly", false},
		{"q=off", false},
		{"q=hello", false},
	} {
		res, err := eng.Check(httptest.NewRequest("GET", "/?"+tc.query, nil), "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		if res.Blocked != tc.block || (tc.block && res.RuleID != 1000001) {
			t.Errorf("%s: blocked=%v rule=%d", tc.query, res.Blocked, res.RuleID)
		}
	}
}
