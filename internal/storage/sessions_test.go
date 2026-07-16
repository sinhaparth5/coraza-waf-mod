package storage

import (
	"testing"
	"time"
)

// TestPruneExpiredSessions verifies expired rows are actually deleted (not
// just rejected at read time by ValidateSession) while live sessions survive,
// and that CreateSession sweeps opportunistically on login.
func TestPruneExpiredSessions(t *testing.T) {
	db := openTestDB(t)

	insert := func(token string, age time.Duration) {
		t.Helper()
		_, err := db.exec(
			`INSERT INTO sessions (token, created_at) VALUES (?, ?)`,
			token, time.Now().UTC().Add(-age).Format(time.RFC3339),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := db.queryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	insert("stale", sessionTTL+time.Hour)
	insert("fresh", time.Minute)

	n, err := db.PruneExpiredSessions()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || count() != 1 {
		t.Errorf("prune deleted %d rows, %d remain; want 1 deleted, 1 remaining", n, count())
	}
	if valid, _ := db.ValidateSession("fresh"); !valid {
		t.Error("fresh session no longer valid after prune")
	}

	// CreateSession sweeps on login: a stale row disappears, leaving the
	// surviving fresh row plus the newly created one.
	insert("stale2", sessionTTL+time.Hour)
	if _, err := db.CreateSession(); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Errorf("sessions after CreateSession sweep = %d, want 2 (fresh + new)", got)
	}
}
