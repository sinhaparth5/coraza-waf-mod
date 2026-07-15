package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"coraza-waf-mod/internal/storage"
)

// captureServer records every POSTed body and its Content-Type, returning a
// fixed status code.
type captureServer struct {
	mu     sync.Mutex
	bodies [][]byte
	ct     []string
	status int
	*httptest.Server
}

func newCaptureServer(status int) *captureServer {
	s := &captureServer{status: status}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		s.mu.Lock()
		s.bodies = append(s.bodies, body)
		s.ct = append(s.ct, r.Header.Get("Content-Type"))
		s.mu.Unlock()
		w.WriteHeader(s.status)
	}))
	return s
}

func (s *captureServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func (s *captureServer) last() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bodies) == 0 {
		return nil
	}
	return s.bodies[len(s.bodies)-1]
}

func TestPusherPushDeliversMatchingEventOnly(t *testing.T) {
	srv := newCaptureServer(200)
	defer srv.Close()

	cfg := storage.WebhookConfig{URL: srv.URL, Enabled: true, Events: "blocked", DestinationType: "generic"}
	p := New(func() (storage.WebhookConfig, error) { return cfg, nil })
	defer p.Stop()

	p.deliver(storage.RequestLog{Action: "proxied", Status: 200})
	if got := srv.count(); got != 0 {
		t.Fatalf("non-matching event delivered %d times, want 0", got)
	}

	blocked := storage.RequestLog{Blocked: true, Status: 403, Action: "waf_rule", RealIP: "203.0.113.9"}
	p.deliver(blocked)
	if got := srv.count(); got != 1 {
		t.Fatalf("matching event delivered %d times, want 1", got)
	}
	var decoded storage.RequestLog
	if err := json.Unmarshal(srv.last(), &decoded); err != nil {
		t.Fatalf("generic body not the raw RequestLog: %v", err)
	}
	if decoded.RealIP != "203.0.113.9" {
		t.Errorf("delivered RealIP = %q, want 203.0.113.9", decoded.RealIP)
	}
}

func TestPusherDeliverDisabledOrNoURLSkips(t *testing.T) {
	srv := newCaptureServer(200)
	defer srv.Close()

	for name, cfg := range map[string]storage.WebhookConfig{
		"disabled": {URL: srv.URL, Enabled: false, Events: "all"},
		"no url":   {URL: "", Enabled: true, Events: "all"},
	} {
		p := New(func() (storage.WebhookConfig, error) { return cfg, nil })
		p.deliver(storage.RequestLog{Blocked: true})
		p.Stop()
		if got := srv.count(); got != 0 {
			t.Errorf("%s: delivered %d times, want 0", name, got)
		}
	}
}

func TestPusherSlackDestinationPostsBlockKit(t *testing.T) {
	srv := newCaptureServer(200)
	defer srv.Close()

	cfg := storage.WebhookConfig{URL: srv.URL, Enabled: true, Events: "all", DestinationType: "slack"}
	p := New(func() (storage.WebhookConfig, error) { return cfg, nil })
	defer p.Stop()

	p.deliver(storage.RequestLog{Blocked: true, Action: "waf_rule"})
	if got := srv.count(); got != 1 {
		t.Fatalf("delivered %d times, want 1", got)
	}
	var decoded struct {
		Attachments []any `json:"attachments"`
	}
	if err := json.Unmarshal(srv.last(), &decoded); err != nil || len(decoded.Attachments) == 0 {
		t.Fatalf("slack destination did not post a Block Kit attachment payload: %v, %s", err, srv.last())
	}
}

func TestPusherSendTestIgnoresEnabledAndEvents(t *testing.T) {
	srv := newCaptureServer(200)
	defer srv.Close()

	cfg := storage.WebhookConfig{URL: srv.URL, Enabled: false, Events: "challenged", DestinationType: "generic"}
	p := New(func() (storage.WebhookConfig, error) { return cfg, nil })
	defer p.Stop()

	if err := p.SendTest(); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("SendTest delivered %d times, want 1", got)
	}
}

func TestPusherSendTestRequiresURL(t *testing.T) {
	p := New(func() (storage.WebhookConfig, error) { return storage.WebhookConfig{}, nil })
	defer p.Stop()
	if err := p.SendTest(); err == nil {
		t.Fatal("SendTest with no URL configured should error, got nil")
	}
}

func TestPusherPostReportsNonSuccessStatus(t *testing.T) {
	srv := newCaptureServer(500)
	defer srv.Close()

	cfg := storage.WebhookConfig{URL: srv.URL, Enabled: true}
	p := New(func() (storage.WebhookConfig, error) { return cfg, nil })
	defer p.Stop()

	if err := p.post(cfg, storage.RequestLog{Blocked: true}); err == nil {
		t.Fatal("post against a 500-returning endpoint should error, got nil")
	}
}
