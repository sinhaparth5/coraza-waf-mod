package accesslog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

func TestFormatLine(t *testing.T) {
	ts := time.Date(2026, 7, 9, 14, 32, 10, 0, time.FixedZone("", 3600))
	entry := storage.RequestLog{
		RealIP:    "203.0.113.7",
		Timestamp: ts,
		Method:    "GET",
		Path:      "/api/foo",
		Query:     "a=1&b=2",
		Proto:     "HTTP/1.1",
		Status:    200,
		UserAgent: "test-agent/1.0",
	}
	want := `203.0.113.7 - - [09/Jul/2026:14:32:10 +0100] "GET /api/foo?a=1&b=2 HTTP/1.1" 200 - "-" "test-agent/1.0"`
	if got := FormatLine(entry); got != want {
		t.Errorf("FormatLine =\n%q\nwant\n%q", got, want)
	}
}

func TestFormatLineFallbacksForMissingFields(t *testing.T) {
	// RealIP, Proto, and UserAgent can all be empty on a malformed or
	// internally-synthesized entry — must render "-" (nginx's own convention
	// for "no value"), never an empty/broken field.
	entry := storage.RequestLog{Method: "GET", Path: "/", Status: 200}
	got := FormatLine(entry)
	if !strings.HasPrefix(got, "- - - [") {
		t.Errorf("missing RealIP must render as \"-\", got: %q", got)
	}
	if !strings.Contains(got, "GET / HTTP/1.1") {
		t.Errorf("missing Proto must default to HTTP/1.1, got: %q", got)
	}
	if !strings.HasSuffix(got, `"-"`) {
		t.Errorf("missing UserAgent must render as \"-\", got: %q", got)
	}
}

func TestWriterPushAppendsFormattedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	w, err := New(path, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	entries := []storage.RequestLog{
		{RealIP: "1.1.1.1", Method: "GET", Path: "/a", Proto: "HTTP/1.1", Status: 200},
		{RealIP: "2.2.2.2", Method: "POST", Path: "/b", Proto: "HTTP/1.1", Status: 404},
	}
	for _, e := range entries {
		w.Push(e)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), data)
	}
	for i, e := range entries {
		if lines[i] != FormatLine(e) {
			t.Errorf("line %d = %q, want %q", i, lines[i], FormatLine(e))
		}
	}
}

func TestWriterPushAfterCloseIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	w, err := New(path, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close must be a safe no-op, got: %v", err)
	}
	// Must not panic or write to the now-closed file descriptor.
	w.Push(storage.RequestLog{Method: "GET", Path: "/", Status: 200})
}

// TestWriterRotation constructs a Writer directly (same package, so
// unexported fields are reachable) with a tiny byte threshold rather than
// going through New's whole-megabyte granularity — avoids writing tens of
// thousands of lines just to cross 1MB in a unit test.
func TestWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	w := &Writer{f: f, path: path, maxSizeBytes: 60, maxBackups: 2}

	// Each formatted line is well over 60 bytes, so every Push after the
	// first should trigger a rotation.
	for i := 0; i < 5; i++ {
		w.Push(storage.RequestLog{
			RealIP: "203.0.113.7", Method: "GET", Path: fmt.Sprintf("/req-%d", i),
			Proto: "HTTP/1.1", Status: 200, UserAgent: "test-agent",
		})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// maxBackups=2 means we keep access.log, access.log.1, access.log.2 —
	// access.log.3 must not exist (pruned).
	for _, suffix := range []string{"", ".1", ".2"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Errorf("expected %s to exist: %v", path+suffix, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("expected %s.3 to be pruned beyond maxBackups=2, stat err: %v", path, err)
	}

	// The newest entry (req-4) must be in the current (non-rotated) file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/req-4") {
		t.Errorf("current file missing the most recent entry, got:\n%s", data)
	}
}

func TestWriterRotationWithZeroBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	w := &Writer{f: f, path: path, maxSizeBytes: 60, maxBackups: 0}

	for i := 0; i < 3; i++ {
		w.Push(storage.RequestLog{RealIP: "1.1.1.1", Method: "GET", Path: fmt.Sprintf("/req-%d", i), Proto: "HTTP/1.1", Status: 200})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("maxBackups=0 must never create %s.1, stat err: %v", path, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("current file must still exist: %v", err)
	}
}
