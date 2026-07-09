package ui

import (
	"sync"

	"coraza-waf-mod/internal/storage"
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
