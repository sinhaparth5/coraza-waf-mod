package blocklist

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"palisade/internal/storage"
)

func openDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCheckPriority(t *testing.T) {
	db := openDB(t)
	for _, r := range [][3]string{
		{"shop", "1.1.1.1", "block"},
		{"shop", "10.0.0.0/8", "allow"},
		{"", "2.2.2.2", "block"},
		{"", "10.0.0.0/8", "block"},
		{"", "192.168.0.0/16", "block"},
		{"", "9.9.9.9", "allow"},
	} {
		if err := db.AddIPRule(r[0], r[1], r[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddThreatIntelSource("feed", "http://example.invalid", 24); err != nil {
		t.Fatal(err)
	}
	srcs, _ := db.ListThreatIntelSources()
	if err := db.ReplaceThreatIntelIPs(srcs[0].ID, []string{"9.9.9.9", "3.3.3.3", "172.16.0.0/12"}); err != nil {
		t.Fatal(err)
	}

	bl, err := NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()

	tests := []struct {
		ip, app    string
		wantBlock  bool
		wantReason string
	}{
		{"1.1.1.1", "shop", true, "ip_blocked"},
		{"1.1.1.1", "other", false, ""},
		{"10.1.2.3", "shop", false, ""}, // per-app allow beats global CIDR block
		{"10.1.2.3", "other", true, "ip_blocked_global"},
		{"2.2.2.2", "shop", true, "ip_blocked_global"},
		{"192.168.1.1", "", true, "ip_blocked_global"},
		{"9.9.9.9", "", false, ""}, // user allow beats intel
		{"3.3.3.3", "", true, "ip_blocked_intel"},
		{"172.16.5.5", "", true, "ip_blocked_intel"},
		{"8.8.8.8", "", false, ""},
		{"not-an-ip", "", false, ""},
	}
	for _, tt := range tests {
		blocked, reason := bl.Check(tt.ip, tt.app)
		if blocked != tt.wantBlock || reason != tt.wantReason {
			t.Errorf("Check(%q,%q) = %v,%q want %v,%q", tt.ip, tt.app, blocked, reason, tt.wantBlock, tt.wantReason)
		}
	}
}

func TestReloadPicksUpNewRules(t *testing.T) {
	db := openDB(t)
	bl, err := NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := bl.Check("4.4.4.4", ""); blocked {
		t.Fatal("blocked before rule exists")
	}
	_ = db.AddIPRule("", "4.4.4.4", "block")
	if err := bl.Reload(db); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := bl.Check("4.4.4.4", ""); !blocked {
		t.Fatal("not blocked after Reload")
	}
}

func TestReloadErrorsOnClosedDB(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	bl, _ := NewIPBlocklist(db)
	db.Close()
	if err := bl.Reload(db); err == nil {
		t.Error("Reload on closed DB should error")
	}
	if err := bl.ReloadIntel(db); err == nil {
		t.Error("ReloadIntel on closed DB should error")
	}
	if _, err := NewIPBlocklist(db); err == nil {
		t.Error("NewIPBlocklist on closed DB should error")
	}
}

func TestEnableClusterSyncUnreachable(t *testing.T) {
	db := openDB(t)
	bl, _ := NewIPBlocklist(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := bl.EnableClusterSync(ctx, "127.0.0.1:1", "", db); err == nil {
		t.Fatal("expected error for unreachable redis")
	}
}

// TestClusterSync needs a real Redis; CI provides one via TEST_REDIS_ADDR.
func TestClusterSync(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	db := openDB(t)
	a, _ := NewIPBlocklist(db)
	b, _ := NewIPBlocklist(db)
	ctx := context.Background()
	for _, bl := range []*IPBlocklist{a, b} {
		if err := bl.EnableClusterSync(ctx, addr, "", db); err != nil {
			t.Fatal(err)
		}
		defer bl.Close()
	}

	_ = db.AddIPRule("", "5.5.5.5", "block")
	if err := a.Reload(db); err != nil { // broadcasts to b
		t.Fatal(err)
	}
	srcs := mustSource(t, db)
	_ = db.ReplaceThreatIntelIPs(srcs, []string{"6.6.6.6"})
	if err := a.ReloadIntel(db); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r1, _ := b.Check("5.5.5.5", "")
		r2, _ := b.Check("6.6.6.6", "")
		if r1 && r2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("peer never picked up broadcast reload")
}

func mustSource(t *testing.T, db *storage.DB) int64 {
	t.Helper()
	if err := db.AddThreatIntelSource("feed", "http://example.invalid", 24); err != nil {
		t.Fatal(err)
	}
	srcs, err := db.ListThreatIntelSources()
	if err != nil || len(srcs) == 0 {
		t.Fatal(err)
	}
	return srcs[0].ID
}
