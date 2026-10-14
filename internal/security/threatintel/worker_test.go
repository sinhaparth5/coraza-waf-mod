package threatintel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"palisade/internal/storage"
)

const feed = `# comment
; another comment

1.2.3.4
5.6.7.0/24 ; trailing note
2001:db8::1
not-an-ip
999.1.1.1
`

func TestFetchIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, feed)
	}))
	defer srv.Close()

	ips, err := fetchIPs(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.2.3.4", "5.6.7.0/24", "2001:db8::1"}
	if !slices.Equal(ips, want) {
		t.Fatalf("fetchIPs = %v, want %v", ips, want)
	}

	if _, err := fetchIPs(srv.Client(), "://bad"); err == nil {
		t.Error("expected error for malformed URL")
	}
	if _, err := fetchIPs(srv.Client(), "http://127.0.0.1:1"); err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestWorkerSyncs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, feed)
	}))
	defer srv.Close()

	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.AddThreatIntelSource("good", srv.URL, 24)
	_ = db.AddThreatIntelSource("dead", "http://127.0.0.1:1", 24)
	_ = db.AddThreatIntelSource("off", srv.URL, 24)
	srcs, _ := db.ListThreatIntelSources()
	for _, s := range srcs {
		if s.Label == "off" {
			_ = db.SetThreatIntelSourceEnabled(s.ID, false)
		}
	}

	var reloads atomic.Int32
	w := New(db, func() { reloads.Add(1) })
	defer w.Stop()
	defer w.Stop() // idempotent

	// The startup pass syncs sources sequentially; wait until both enabled
	// ones have been attempted before asserting.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n := 0
		srcs, _ = db.ListThreatIntelSources()
		for _, s := range srcs {
			if !s.LastSyncedAt.IsZero() || s.LastError != "" {
				n++
			}
		}
		if n == 2 && reloads.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reloads.Load() == 0 {
		t.Fatal("startup sync never ran")
	}

	srcs, _ = db.ListThreatIntelSources()
	for _, s := range srcs {
		switch s.Label {
		case "good":
			if s.IPCount != 3 || s.LastError != "" {
				t.Errorf("good source: %+v", s)
			}
			w.SyncSource(s.ID) // manual re-sync
		case "dead":
			if s.LastError == "" {
				t.Errorf("dead source should record an error: %+v", s)
			}
		case "off":
			if !s.LastSyncedAt.IsZero() {
				t.Errorf("disabled source was synced: %+v", s)
			}
		}
	}
	if reloads.Load() < 2 {
		t.Errorf("SyncSource did not reload, reloads=%d", reloads.Load())
	}
	w.SyncSource(9999) // unknown id is a no-op

	ips, _ := db.ListThreatIntelIPs()
	if len(ips) != 3 {
		t.Errorf("stored IPs = %v", ips)
	}
}
