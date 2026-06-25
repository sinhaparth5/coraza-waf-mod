package ui

import (
	"sync"

	"coraza-waf-mod/storage"
)

const recentBufSize = 200

// LogBroadcaster fans out new log entries to all connected SSE clients
// and keeps a ring buffer of the last 200 entries for page loads.
type LogBroadcaster struct {
	mu     sync.RWMutex
	subs   map[chan storage.RequestLog]struct{}
	recent []storage.RequestLog
}

func NewLogBroadcaster() *LogBroadcaster {
	return &LogBroadcaster{
		subs:   make(map[chan storage.RequestLog]struct{}),
		recent: make([]storage.RequestLog, 0, recentBufSize),
	}
}

func (b *LogBroadcaster) Subscribe() chan storage.RequestLog {
	ch := make(chan storage.RequestLog, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *LogBroadcaster) Unsubscribe(ch chan storage.RequestLog) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *LogBroadcaster) Broadcast(entry storage.RequestLog) {
	b.mu.Lock()
	if len(b.recent) >= recentBufSize {
		b.recent = b.recent[1:]
	}
	b.recent = append(b.recent, entry)
	for ch := range b.subs {
		select {
		case ch <- entry:
		default: // drop if client is slow
		}
	}
	b.mu.Unlock()
}

// SubscriberCount returns how many SSE clients are currently connected
// (notifications stream + logs stream combined, since both share this
// broadcaster) — used to log how many long-lived connections are open, since
// each one permanently occupies one of the browser's ~6-per-origin HTTP/1.1
// connection slots until the tab closes.
func (b *LogBroadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Recent returns a copy of the ring buffer (oldest first).
func (b *LogBroadcaster) Recent() []storage.RequestLog {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]storage.RequestLog, len(b.recent))
	copy(out, b.recent)
	return out
}
