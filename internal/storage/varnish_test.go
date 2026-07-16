package storage

import (
	"testing"
)

func TestVarnishConfigRoundtrip(t *testing.T) {
	db := openTestDB(t)

	// Unset: disabled with the deploy default address.
	cfg, err := db.GetVarnishConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled || cfg.Addr != DefaultVarnishAddr || cfg.ReturnAddr != DefaultVarnishReturnAddr {
		t.Errorf("unset config = %+v, want disabled at %s / return %s", cfg, DefaultVarnishAddr, DefaultVarnishReturnAddr)
	}

	want := VarnishConfig{Enabled: true, Addr: "127.0.0.1:7000", ReturnAddr: "127.0.0.1:7001"}
	if err := db.SetVarnishConfig(want); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetVarnishConfig(); got != want {
		t.Errorf("roundtrip = %+v, want %+v", got, want)
	}
}

func TestServiceCacheEnabledRoundtrip(t *testing.T) {
	db := openTestDB(t)

	if err := db.AddService("app", "app.example.com", "", "http://127.0.0.1:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListServices()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if list[0].CacheEnabled {
		t.Error("new service should default to cache disabled")
	}

	if err := db.SetServiceCache(list[0].ID, true); err != nil {
		t.Fatal(err)
	}
	svc, err := db.GetService(list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !svc.CacheEnabled {
		t.Error("SetServiceCache(true) not persisted")
	}
}
