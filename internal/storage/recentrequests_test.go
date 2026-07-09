package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// TestListRecentRequestLogs exercises the access-log terminal panel's
// history preload: window filtering (excludes anything before `since`),
// the limit keeping the most recent N within that window (not the oldest
// N), and the result coming back in chronological (oldest-first) order so
// client-side appends read top-to-bottom like a real tail -f.
func TestListRecentRequestLogs(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	insert := func(ts time.Time, path string) {
		t.Helper()
		if _, err := db.InsertRequest(RequestLog{
			Timestamp: ts, AppName: "app", RealIP: "203.0.113.7",
			Method: "GET", Host: "h", Path: path, Query: "q=1", Proto: "HTTP/1.1", Status: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Two rows well before the window, five rows inside it.
	insert(base.Add(-48*time.Hour), "/too-old-1")
	insert(base.Add(-25*time.Hour), "/too-old-2")
	insert(base.Add(-3*time.Hour), "/a")
	insert(base.Add(-2*time.Hour), "/b")
	insert(base.Add(-1*time.Hour), "/c")
	insert(base.Add(-30*time.Minute), "/d")
	insert(base, "/e")

	since := base.Add(-24 * time.Hour)

	// No limit constraint (large limit): all 5 in-window rows, oldest first.
	got, err := db.ListRecentRequestLogs(since, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"/a", "/b", "/c", "/d", "/e"}
	if len(got) != len(wantPaths) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(wantPaths), got)
	}
	for i, want := range wantPaths {
		if got[i].Path != want {
			t.Errorf("row %d Path = %q, want %q (order must be oldest-first)", i, got[i].Path, want)
		}
	}
	if got[0].Query != "q=1" || got[0].Proto != "HTTP/1.1" {
		t.Errorf("row 0 = %+v, want Query=q=1 Proto=HTTP/1.1 (fields FormatLine needs, not in LogRow)", got[0])
	}

	// Limit=3 within the same window must keep the 3 MOST RECENT rows
	// (/c, /d, /e), not the 3 oldest — still returned oldest-first.
	got, err = db.ListRecentRequestLogs(since, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths = []string{"/c", "/d", "/e"}
	if len(got) != len(wantPaths) {
		t.Fatalf("limited: got %d rows, want %d: %+v", len(got), len(wantPaths), got)
	}
	for i, want := range wantPaths {
		if got[i].Path != want {
			t.Errorf("limited row %d Path = %q, want %q", i, got[i].Path, want)
		}
	}
}
