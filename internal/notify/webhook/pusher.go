package webhook

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/internal/storage"
)

// Pusher receives security events from the log worker and delivers them to a
// configured HTTP endpoint. The payload shape depends on the configured
// destination type (storage.WebhookConfig.DestinationType): "generic" posts
// the raw RequestLog as JSON (the original, unchanged behavior); "slack" and
// "discord" post that platform's rich-message format instead — see
// format.go. It runs in the background so a slow or unavailable webhook
// never slows down the request path.
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
	if err := p.post(cfg, entry); err != nil {
		log.Printf("webhook: %v", err)
	}
}

// SendTest delivers a single synthetic "blocked" event to the currently
// saved endpoint/destination type, bypassing both the Enabled flag and the
// Events filter — mirrors mailer.Reporter.SendNow, which works the same way
// (against saved settings, ignoring the enabled toggle) so the Settings page
// can offer a "send test alert" button that proves the URL and formatting
// are right before the admin flips delivery on.
func (p *Pusher) SendTest() error {
	cfg, err := p.getConfig()
	if err != nil {
		return err
	}
	if cfg.URL == "" {
		return errors.New("no webhook URL configured")
	}
	test := storage.RequestLog{
		Timestamp: time.Now(),
		AppName:   "test",
		RealIP:    "203.0.113.1",
		Method:    "GET",
		Path:      "/test",
		Status:    403,
		Blocked:   true,
		RuleID:    942100,
		Action:    "waf_rule",
	}
	return p.post(cfg, test)
}

// post builds the destination-appropriate payload and delivers it.
func (p *Pusher) post(cfg storage.WebhookConfig, entry storage.RequestLog) error {
	body, err := buildPayload(cfg.DestinationType, entry)
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "coraza-waf-mod/internal/notify/webhook")
	if cfg.Secret != "" {
		req.Header.Set("X-WAF-Secret", cfg.Secret)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("delivery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// shouldSend returns true if the entry's event category is in the
// comma-separated events string. Categories: "blocked", "challenged",
// "proxied". "all" matches everything.
func (p *Pusher) shouldSend(events string, entry storage.RequestLog) bool {
	category := eventCategory(entry)
	for _, e := range strings.Split(events, ",") {
		e = strings.TrimSpace(e)
		if e == "all" || e == category {
			return true
		}
	}
	return false
}
