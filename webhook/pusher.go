package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/storage"
)

// Pusher receives security events from the log worker and delivers them to a
// configured HTTP endpoint as JSON POST requests. It runs in the background so
// a slow or unavailable webhook never slows down the request path.
type Pusher struct {
	queue     chan storage.RequestLog
	stop      chan struct{}
	once      sync.Once
	client    *http.Client
	getConfig func() (storage.WebhookConfig, error)
}

// New creates a Pusher and starts the background delivery goroutine.
// getConfig is called on every delivery so config changes take effect
// without a restart.
func New(getConfig func() (storage.WebhookConfig, error)) *Pusher {
	p := &Pusher{
		queue:     make(chan storage.RequestLog, 500),
		stop:      make(chan struct{}),
		client:    &http.Client{Timeout: 5 * time.Second},
		getConfig: getConfig,
	}
	go p.run()
	return p
}

// Push enqueues an entry for delivery. Drops silently if the queue is full so
// a stalled or slow endpoint never blocks the log worker goroutine.
func (p *Pusher) Push(entry storage.RequestLog) {
	select {
	case p.queue <- entry:
	default:
	}
}

// Stop shuts down the delivery goroutine.
func (p *Pusher) Stop() {
	p.once.Do(func() { close(p.stop) })
}

func (p *Pusher) run() {
	for {
		select {
		case entry := <-p.queue:
			p.deliver(entry)
		case <-p.stop:
			return
		}
	}
}

func (p *Pusher) deliver(entry storage.RequestLog) {
	cfg, err := p.getConfig()
	if err != nil || !cfg.Enabled || cfg.URL == "" {
		return
	}
	if !p.shouldSend(cfg.Events, entry) {
		return
	}

	body, err := json.Marshal(entry)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "coraza-waf-mod/webhook")
	if cfg.Secret != "" {
		req.Header.Set("X-WAF-Secret", cfg.Secret)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("webhook: delivery failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("webhook: endpoint returned %d", resp.StatusCode)
	}
}

// shouldSend returns true if the entry's event category is in the comma-separated
// events string. Categories: "blocked", "challenged". "all" matches everything.
func (p *Pusher) shouldSend(events string, entry storage.RequestLog) bool {
	category := "proxied"
	if entry.Blocked {
		category = "blocked"
	} else if entry.Action == "bot_challenge" {
		category = "challenged"
	}
	for _, e := range strings.Split(events, ",") {
		e = strings.TrimSpace(e)
		if e == "all" || e == category {
			return true
		}
	}
	return false
}
