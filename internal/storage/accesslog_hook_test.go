package storage

import (
	"testing"
	"time"
)

// TestAccessLogFnFires confirms SetAccessLogFn's hook actually gets called
// from QueueRequest -> runLogWorker's async pipeline, the same fan-out point
// webhook/autoban/broadcast already use — a regression here would silently
// mean the access.log writer (internal/notify/accesslog) never receives any
// entries despite being wired up correctly in main.go.
func TestAccessLogFnFires(t *testing.T) {
	db := openTestDB(t)

	got := make(chan RequestLog, 1)
	db.SetAccessLogFn(func(e RequestLog) { got <- e })

	db.QueueRequest(RequestLog{Method: "GET", Path: "/hook-test", Status: 200, Timestamp: time.Now()})

	select {
	case e := <-got:
		if e.Path != "/hook-test" {
			t.Errorf("hook received %+v, want Path=/hook-test", e)
		}
		if e.ID == 0 {
			t.Error("hook fired before the DB insert assigned a real row ID (fired out of order relative to broadcast/webhook/autoban)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("access log hook never fired")
	}
}

// TestAccessLogFnNilIsSafe confirms a nil hook (the default — main.go only
// calls SetAccessLogFn when --access-log is set) never panics runLogWorker.
func TestAccessLogFnNilIsSafe(t *testing.T) {
	db := openTestDB(t)

	db.QueueRequest(RequestLog{Method: "GET", Path: "/no-hook", Status: 200, Timestamp: time.Now()})
	// If runLogWorker panicked on a nil accessLogFn, this Close (which drains
	// the queue) would hang or the goroutine would have already crashed the
	// process; reaching here at all is the assertion.
}
