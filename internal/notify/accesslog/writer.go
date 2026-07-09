// Package accesslog writes an nginx-combined-format access.log file fed from
// the same log fan-out pipeline as the webhook pusher and autoban scorer
// (see storage.DB.SetAccessLogFn) — a flat text log for tooling that expects
// one (fail2ban, log shippers, grep/awk, logrotate), independent of the
// SQLite-backed admin UI.
package accesslog

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"coraza-waf-mod/internal/storage"
)

const timeLayout = "02/Jan/2006:15:04:05 -0700"

// FormatLine renders one nginx combined-format log line for entry:
//
//	IP - - [time] "METHOD path?query PROTO" status bytes "referer" "user-agent"
//
// storage.RequestLog doesn't track response byte count or the Referer
// header, so both render as "-" — nginx's own convention for "no value",
// the same placeholder already used here for the identd/userid fields.
// Exported so the file writer and the dashboard's live SSE panel render
// byte-identical lines from one source of truth.
func FormatLine(e storage.RequestLog) string {
	ip := e.RealIP
	if ip == "" {
		ip = "-"
	}
	proto := e.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	ua := e.UserAgent
	if ua == "" {
		ua = "-"
	}
	uri := e.Path
	if e.Query != "" {
		uri += "?" + e.Query
	}

	return fmt.Sprintf(`%s - - [%s] "%s %s %s" %d - "-" "%s"`,
		ip, e.Timestamp.Format(timeLayout), e.Method, uri, proto, e.Status, ua)
}

// Writer owns the open access.log file and its in-house size-based
// rotation. Push is always called from storage's single runLogWorker
// goroutine (the same serialization every other log fan-out hook —
// webhook, autoban, broadcast — relies on), so writes need no locking;
// the mutex here only guards against Close racing a write during shutdown,
// the same class of race that already exists for webhookPusher/banner.
type Writer struct {
	mu           sync.Mutex
	f            *os.File
	path         string
	size         int64
	maxSizeBytes int64
	maxBackups   int
	closed       bool
}

// New opens (or creates) path in append mode. maxSizeMB and maxBackups
// control in-house rotation: once a write would push the file past
// maxSizeMB, the current file is rotated to path.1 (shifting any existing
// path.1..path.N up by one, dropping anything beyond maxBackups) before the
// write proceeds.
func New(path string, maxSizeMB, maxBackups int) (*Writer, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 100
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("access log: create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("access log: open %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close() //nolint
		return nil, fmt.Errorf("access log: stat %s: %w", path, err)
	}
	return &Writer{
		f:            f,
		path:         path,
		size:         st.Size(),
		maxSizeBytes: int64(maxSizeMB) * 1024 * 1024,
		maxBackups:   maxBackups,
	}, nil
}

// Push formats and appends one line for entry, rotating first if needed.
// Matches the func(storage.RequestLog) hook signature storage.DB expects
// (see SetAccessLogFn) — errors are logged, never returned or propagated,
// same as every other log fan-out hook in this codebase.
func (w *Writer) Push(entry storage.RequestLog) {
	line := FormatLine(entry) + "\n"

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if w.size+int64(len(line)) > w.maxSizeBytes {
		if err := w.rotateLocked(); err != nil {
			log.Printf("access log: rotate: %v", err)
			// Fall through and keep writing to the current file — a failed
			// rotation shouldn't also lose the line that triggered it.
		}
	}
	n, err := w.f.WriteString(line)
	if err != nil {
		log.Printf("access log: write: %v", err)
		return
	}
	w.size += int64(n)
}

// rotateLocked shifts path.(N-1) -> path.N ... path.1 -> path.2, drops
// anything beyond maxBackups, moves the current file to path.1, and opens a
// fresh path. Caller must hold w.mu.
func (w *Writer) rotateLocked() error {
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("close current file: %w", err)
	}

	if w.maxBackups > 0 {
		oldest := fmt.Sprintf("%s.%d", w.path, w.maxBackups)
		if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
			log.Printf("access log: remove oldest backup %s: %v", oldest, err)
		}
		for i := w.maxBackups - 1; i >= 1; i-- {
			from := fmt.Sprintf("%s.%d", w.path, i)
			to := fmt.Sprintf("%s.%d", w.path, i+1)
			if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
				log.Printf("access log: rotate %s -> %s: %v", from, to, err)
			}
		}
		if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
			log.Printf("access log: rotate %s -> %s.1: %v", w.path, w.path, err)
		}
	} else {
		// No backups kept: rotation just means "start over".
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			log.Printf("access log: remove %s: %v", w.path, err)
		}
	}

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("reopen %s: %w", w.path, err)
	}
	w.f = f
	w.size = 0
	return nil
}

// Close flushes and closes the underlying file. Safe to call once; a
// subsequent Push after Close is a silent no-op rather than a write-after-
// close error, since it can race storage's log-worker drain on shutdown
// (see main.go's defer ordering relative to db.Close).
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}
