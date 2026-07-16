package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// TestMigrateConfigTo populates a fresh SQLite source across every migrated
// table (services, IP/geo rules, certificates, API keys, WAF rule
// overrides, threat-intel sources + synced IPs, webhook config, IP threat
// scores, JA4 reputation, and meta/settings) and migrates it into whatever
// backend openTestDB targets — plain SQLite by default (TEST_DB_DRIVER
// unset), or a live MySQL/Postgres container in CI (TEST_DB_DRIVER set, see
// ci.yml's test-external-db job). Confirms row counts, preserved primary
// keys, and that the target's own auto-increment/identity sequence keeps
// working for a normal insert made after the migration.
func TestMigrateConfigTo(t *testing.T) {
	source, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	certID, err := source.AddCertificate("cert1", "example.com", "", "/c", "/k")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.AddService("svc1", "svc1.example.com", "", "http://127.0.0.1:9000", 5, 10); err != nil {
		t.Fatal(err)
	}
	if err := source.SetServiceCache(1, true); err != nil {
		t.Fatal(err)
	}
	if err := source.AddIPRuleWithNote("", "203.0.113.5", "block", "test note"); err != nil {
		t.Fatal(err)
	}
	if err := source.AddGeoRule("", "ZZ", "block"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CreateAPIKey("key1", "cwaf_abc", "somehash"); err != nil {
		t.Fatal(err)
	}
	if err := source.DisableWAFRule(942100, "false positive"); err != nil {
		t.Fatal(err)
	}
	if err := source.DisableWAFRuleForService("svc1", 942200, "svc-specific"); err != nil {
		t.Fatal(err)
	}
	if err := source.AddThreatIntelSource("Test list", "https://example.com/list.txt", 24); err != nil {
		t.Fatal(err)
	}
	if err := source.ReplaceThreatIntelIPs(1, []string{"1.1.1.1", "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	if err := source.SetWebhookConfig(WebhookConfig{
		URL: "https://hooks.example.com", Secret: "whsecret", Enabled: true, Events: "blocked", DestinationType: "slack",
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.UpsertIPThreatScore(IPThreatScore{IP: "203.0.113.5", Total: 42, AutobanScore: 10, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.BumpJA4Reputation("t13d1516h2_abcdef", true); err != nil {
		t.Fatal(err)
	}

	targetDriver, targetDSN := testTargetDriverDSN(t)
	report, err := source.MigrateConfigTo(targetDriver, targetDSN)
	if err != nil {
		t.Fatalf("MigrateConfigTo: %v (partial report: %+v)", err, report)
	}
	for _, tr := range report.Tables {
		if tr.Rows == 0 {
			t.Errorf("table %s migrated 0 rows, want at least 1", tr.Table)
		}
	}
	if report.TotalRows == 0 {
		t.Fatal("expected some rows to migrate")
	}

	target, err := OpenWithDriver(targetDriver, targetDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	svcs, err := target.ListServices()
	if err != nil || len(svcs) != 1 || svcs[0].Name != "svc1" || !svcs[0].CacheEnabled {
		t.Errorf("target services = %+v, %v", svcs, err)
	}
	rules, err := target.ListIPRules()
	if err != nil || len(rules) != 1 || rules[0].Note != "test note" {
		t.Errorf("target ip_rules = %+v, %v", rules, err)
	}
	keys, err := target.ListAPIKeys()
	if err != nil || len(keys) != 1 || keys[0].Name != "key1" {
		t.Errorf("target api_keys = %+v, %v", keys, err)
	}
	wh, err := target.GetWebhookConfig()
	if err != nil || wh.URL != "https://hooks.example.com" || wh.Secret != "whsecret" {
		t.Errorf("target webhook_config = %+v, %v", wh, err)
	}
	score, ok, err := target.GetIPThreatScore("203.0.113.5")
	if err != nil || !ok || score.Total != 42 {
		t.Errorf("target ip_threat_scores = %+v, %v, %v", score, ok, err)
	}
	certs, err := target.ListCertificates()
	if err != nil || len(certs) != 1 || certs[0].ID != certID {
		t.Errorf("target certificates = %+v, want id=%d, %v", certs, certID, err)
	}

	// A normal (non-migrated, auto-assigned-id) insert after the migration
	// must still work — proves preserving explicit ids during migration
	// didn't desynchronize the target's auto-increment/identity sequence.
	if err := target.AddGeoRule("", "PM", "block"); err != nil {
		t.Errorf("normal insert after migration failed (sequence may be broken): %v", err)
	}
}
