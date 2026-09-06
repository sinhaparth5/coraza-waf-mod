package storage

import (
	"testing"
	"time"
)

// TestPruneExpiredSessions verifies rows past sessionHistoryTTL are actually
// deleted (expiry alone is only enforced at read time, so abandoned rows
// would otherwise accumulate forever) while newer rows survive as the device
// history the Settings page lists.
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

	insert("ancient", sessionHistoryTTL+time.Hour)
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

	// An expired-but-not-ancient row still authenticates nothing, but is
	// deliberately kept as history rather than pruned.
	insert("expired", sessionTTL+time.Hour)
	if valid, _ := db.ValidateSession("expired"); valid {
		t.Error("session past sessionTTL still validates")
	}
	if _, err := db.PruneExpiredSessions(); err != nil {
		t.Fatal(err)
	}
	if count() != 2 {
		t.Errorf("sessions after prune = %d, want 2 (expired row kept as history)", count())
	}
}

// TestCreateSessionSingleActive is the core of the single-active-session
// rule: a new login revokes whatever was live, so the older device stops
// authenticating and can tell it was signed out rather than timed out.
func TestCreateSessionSingleActive(t *testing.T) {
	db := openTestDB(t)

	deviceA, err := db.CreateSession("10.0.0.1", "Mozilla/5.0 (Macintosh) Firefox/130.0")
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := db.ValidateSession(deviceA); !valid {
		t.Fatal("device A session not valid immediately after login")
	}

	deviceB, err := db.CreateSession("10.0.0.2", "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0")
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := db.ValidateSession(deviceB); !valid {
		t.Error("device B session not valid immediately after login")
	}
	if valid, _ := db.ValidateSession(deviceA); valid {
		t.Error("device A still valid after device B logged in; single-session rule not enforced")
	}

	// A stops working, but the row survives so the login page can say why
	// and the Settings card can still list the device.
	a, err := db.GetSession(deviceA)
	if err != nil || a == nil {
		t.Fatalf("device A row gone: %v", err)
	}
	if !a.Revoked() || a.Expired() {
		t.Errorf("device A revoked=%v expired=%v; want revoked, not expired", a.Revoked(), a.Expired())
	}
	if a.IP != "10.0.0.1" || a.UserAgent == "" {
		t.Errorf("device metadata not captured: ip=%q ua=%q", a.IP, a.UserAgent)
	}

	// Revoking the one live session leaves nothing authenticating.
	if _, err := db.RevokeOtherSessions("none-of-them"); err != nil {
		t.Fatal(err)
	}
	if valid, _ := db.ValidateSession(deviceB); valid {
		t.Error("device B still valid after RevokeOtherSessions")
	}
	if sessions, err := db.ListSessions(); err != nil || len(sessions) != 2 {
		t.Errorf("ListSessions = %d rows (err %v), want 2", len(sessions), err)
	}
}

// TestListSessionsLiveFirst pins the live session to the top of the device
// list even when both logins land in the same RFC3339 second, which is what
// the card relies on to show "This device" first.
func TestListSessionsLiveFirst(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339)
	for _, tok := range []string{"dead-a", "dead-b"} {
		if _, err := db.exec(
			`INSERT INTO sessions (token, created_at, revoked_at) VALUES (?, ?, ?)`,
			tok, now, now); err != nil {
			t.Fatal(err)
		}
	}
	live, err := db.CreateSession("10.0.0.9", "curl/8.5.0")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := db.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 3 {
		t.Fatalf("ListSessions = %d rows, want 3", len(sessions))
	}
	if sessions[0].Token != live || !sessions[0].Live() {
		t.Errorf("first row = %q (live=%v), want the live session %q",
			sessions[0].Token, sessions[0].Live(), live)
	}
}
