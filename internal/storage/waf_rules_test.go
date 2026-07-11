package storage

import (
	"path/filepath"
	"testing"
)

// TestWAFServiceRuleExceptions exercises disable/list/enable for per-service
// WAF rule exceptions (waf_service_rule_exceptions), and confirms they stay
// independent of the global waf_disabled_rules list — a rule scoped to one
// service must not appear as disabled for another, and the global list
// (used to seed every engine) must never include service-scoped rows.
func TestWAFServiceRuleExceptions(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Global disable for rule 942100, unrelated to any service.
	if err := db.DisableWAFRule(942100, "global false positive"); err != nil {
		t.Fatal(err)
	}

	// Per-service exception: 911100 disabled only for "gemsofcongress".
	if err := db.DisableWAFRuleForService("gemsofcongress", 911100, "REST API uses PATCH/PUT/DELETE"); err != nil {
		t.Fatal(err)
	}
	// A second service gets its own, different exception.
	if err := db.DisableWAFRuleForService("other-svc", 920420, "custom content type"); err != nil {
		t.Fatal(err)
	}

	globalIDs, err := db.GetDisabledWAFRuleIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(globalIDs) != 1 || globalIDs[0] != 942100 {
		t.Fatalf("GetDisabledWAFRuleIDs() = %v, want [942100] (service-scoped rows must not leak into the global list)", globalIDs)
	}

	gemIDs, err := db.GetWAFRuleIDsForService("gemsofcongress")
	if err != nil {
		t.Fatal(err)
	}
	if len(gemIDs) != 1 || gemIDs[0] != 911100 {
		t.Fatalf("GetWAFRuleIDsForService(gemsofcongress) = %v, want [911100]", gemIDs)
	}

	// A service with no exceptions of its own gets none back (and must not
	// see another service's exception).
	noneIDs, err := db.GetWAFRuleIDsForService("unrelated-svc")
	if err != nil {
		t.Fatal(err)
	}
	if len(noneIDs) != 0 {
		t.Fatalf("GetWAFRuleIDsForService(unrelated-svc) = %v, want none", noneIDs)
	}

	names, err := db.ListWAFExceptionServiceNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("ListWAFExceptionServiceNames() = %v, want 2 names", names)
	}

	exceptions, err := db.ListWAFServiceExceptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(exceptions) != 2 {
		t.Fatalf("ListWAFServiceExceptions() = %+v, want 2 rows", exceptions)
	}

	// Re-disabling the same (service, rule) pair updates the reason in place
	// rather than creating a duplicate row (ON CONFLICT DO UPDATE).
	if err := db.DisableWAFRuleForService("gemsofcongress", 911100, "updated reason"); err != nil {
		t.Fatal(err)
	}
	exceptions, err = db.ListWAFServiceExceptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(exceptions) != 2 {
		t.Fatalf("ListWAFServiceExceptions() after re-disable = %+v, want still 2 rows (updated in place)", exceptions)
	}

	// Enable (remove) the gemsofcongress exception by row ID.
	var gemRowID int64
	for _, e := range exceptions {
		if e.ServiceName == "gemsofcongress" && e.RuleID == 911100 {
			gemRowID = e.ID
		}
	}
	if gemRowID == 0 {
		t.Fatal("could not find gemsofcongress exception row to enable")
	}
	if err := db.EnableWAFRuleForService(gemRowID); err != nil {
		t.Fatal(err)
	}

	gemIDs, err = db.GetWAFRuleIDsForService("gemsofcongress")
	if err != nil {
		t.Fatal(err)
	}
	if len(gemIDs) != 0 {
		t.Fatalf("GetWAFRuleIDsForService(gemsofcongress) after enable = %v, want none", gemIDs)
	}

	names, err = db.ListWAFExceptionServiceNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "other-svc" {
		t.Fatalf("ListWAFExceptionServiceNames() after enable = %v, want [other-svc]", names)
	}
}
