package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// TestJA4RoundTrip verifies the ja4 column exists after migration and that a
// fingerprint survives InsertRequest → GetRequestByID → ExportRequests.
func TestJA4RoundTrip(t *testing.T) {
	db := openTestDB(t)

	const ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
	const visitorID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	id, err := db.InsertRequest(RequestLog{
		Timestamp:   time.Now().UTC(),
		AppName:     "app",
		RealIP:      "192.0.2.1",
		Method:      "GET",
		Host:        "example.com",
		Path:        "/",
		Status:      200,
		JA3Hash:     "0123456789abcdef0123456789abcdef",
		JA4:         ja4,
		VisitorID:   visitorID,
		CacheStatus: "HIT",
	})
	if err != nil {
		t.Fatal(err)
	}

	d, err := db.GetRequestByID(int(id))
	if err != nil {
		t.Fatal(err)
	}
	if d.JA4 != ja4 {
		t.Errorf("GetRequestByID JA4 = %q, want %q", d.JA4, ja4)
	}
	if d.JA3Hash == "" {
		t.Error("GetRequestByID lost the legacy JA3 hash")
	}
	if d.VisitorID != visitorID {
		t.Errorf("GetRequestByID VisitorID = %q, want %q", d.VisitorID, visitorID)
	}
	if d.CacheStatus != "HIT" {
		t.Errorf("GetRequestByID CacheStatus = %q, want HIT", d.CacheStatus)
	}

	found := false
	if err := db.ExportRequests(LogFilter{}, func(r RequestLog) bool {
		found = r.JA4 == ja4
		return false
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("ExportRequests did not return the stored JA4 fingerprint")
	}
}

// TestJA4ColumnMigration ensures Open() adds the ja4 column to a database
// created before the column existed (simulated by dropping it).
func TestJA4ColumnMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`ALTER TABLE requests DROP COLUMN ja4`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	db.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var n int
	if err := db2.conn.QueryRow(
		`SELECT count(*) FROM pragma_table_info('requests') WHERE name = 'ja4'`,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("ja4 column was not re-added by migration on an old database")
	}
}

func TestCacheResultsSince(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	for _, r := range []struct {
		app, status string
		ts          time.Time
	}{
		{"shop", "HIT", now}, {"shop", "HIT", now}, {"shop", "MISS", now}, {"shop", "PASS", now},
		{"blog", "MISS", now},
		{"blog", "HIT", now.Add(-48 * time.Hour)}, // outside the window
		{"api", "", now},                          // not cache-routed
	} {
		if _, err := db.InsertRequest(RequestLog{Timestamp: r.ts, AppName: r.app, CacheStatus: r.status}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.CacheResultsSince(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := []CacheResult{{App: "blog", Misses: 1}, {App: "shop", Hits: 2, Misses: 1, Passes: 1}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
