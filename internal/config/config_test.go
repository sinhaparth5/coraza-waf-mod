package config

import "testing"

func TestDefaults(t *testing.T) {
	c := Defaults()
	if c.ListenAddr != ":8080" || c.DB.Path != "waf.db" || c.DB.Driver != "sqlite" ||
		c.DB.LogRetentionDays != 30 || c.Admin.Path != "/admin" || !c.WAF.Enabled ||
		c.TLS.CacheDir != "./certs" || c.RateLimit.Burst != 20 || c.BotProtection.AnomalyThreshold != 8 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if Defaults() == c {
		t.Fatal("Defaults must return a fresh value each call")
	}
}
