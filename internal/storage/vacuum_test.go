package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVacuumReclaimsSpaceAfterPrune pins the reason `prune --vacuum` exists:
// PruneOldRequests alone leaves the file at its high-water mark (DELETE only
// free-lists pages), and Vacuum is what actually hands the space back to the
// OS. Sizes sum the main file plus the -wal sidecar, since Vacuum's rebuild
// is written through the WAL and its trailing TRUNCATE checkpoint is what
// folds that back down.
func TestVacuumReclaimsSpaceAfterPrune(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Bloat the requests table well past SQLite's page-size granularity so
	// the before/after comparison can't flake on rounding.
	filler := strings.Repeat("x", 1024)
	old := time.Now().UTC().AddDate(0, 0, -60)
	for i := 0; i < 2000; i++ {
		if _, err := db.InsertRequest(RequestLog{
			Timestamp: old, AppName: "app", RealIP: "203.0.113.7",
			Method: "GET", Host: "h", Path: "/" + filler, UserAgent: filler, Status: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}

	size := func() int64 {
		var total int64
		for _, p := range []string{path, path + "-wal"} {
			if fi, err := os.Stat(p); err == nil {
				total += fi.Size()
			}
		}
		return total
	}
	bloated := size()

	n, err := db.PruneOldRequests(30)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2000 {
		t.Fatalf("pruned %d rows, want 2000", n)
	}

	if err := db.Vacuum(); err != nil {
		t.Fatal(err)
	}
	if after := size(); after >= bloated/2 {
		t.Errorf("vacuum after full prune left %d bytes on disk (bloated size %d); expected the rebuild to shrink the file", after, bloated)
	}
}
