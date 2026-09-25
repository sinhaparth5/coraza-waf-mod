package ui

import (
	"testing"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/security/waf"
	"coraza-waf-mod/internal/storage"
)

func TestDryRunDiffReportsOnlyChangedVerdicts(t *testing.T) {
	cfg := config.WAFConfig{Enabled: true}
	base, err := waf.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := waf.NewWithDirectives(cfg, nil,
		`SecRule ARGS:q "@streq canary" "id:1000001,phase:1,deny,status:403"`)
	if err != nil {
		t.Fatal(err)
	}
	hdr := `{"User-Agent":"Mozilla/5.0","Accept":"text/html"}`
	logs := []storage.RequestLog{
		{ID: 1, Method: "GET", Host: "a.test", Path: "/", Query: "q=canary", RealIP: "203.0.113.5", HeadersJSON: hdr},
		{ID: 2, Method: "GET", Host: "a.test", Path: "/", Query: "q=hello", RealIP: "203.0.113.5", HeadersJSON: hdr},
	}
	hits, err := dryRunDiff(base, cand, logs)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != 1 || hits[0].Before.Blocked || !hits[0].After.Blocked || hits[0].After.RuleID != 1000001 {
		t.Fatalf("hits = %+v, want only log 1 newly blocked by 1000001", hits)
	}
	if _, err := waf.NewWithDirectives(cfg, nil, "SecRule nonsense"); err == nil {
		t.Fatal("malformed candidate compiled")
	}
}
