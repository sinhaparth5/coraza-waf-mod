package webhook

import (
	"testing"
	"time"

	"palisade/internal/storage"
)

func TestPushNeverBlocksWhenQueueFull(t *testing.T) {
	p := &Pusher{queue: make(chan storage.RequestLog, 1)}
	done := make(chan struct{})
	go func() {
		p.Push(storage.RequestLog{})
		p.Push(storage.RequestLog{}) // full: dropped, not blocked
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Push blocked on a full queue")
	}
}
