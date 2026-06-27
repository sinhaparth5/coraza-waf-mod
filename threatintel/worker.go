package threatintel

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/storage"
)

// Worker periodically fetches external IP block lists and stores the parsed IPs
// in the DB. The blocklist package reads from that store so the WAF picks up
// updates without a server restart.
type Worker struct {
	db         *storage.DB
	reloadIPBL func()
	client     *http.Client
	ticker     *time.Ticker
	stop       chan struct{}
	once       sync.Once
}

// New creates a Worker and starts the background sync loop.
// reloadIPBL is called after each successful sync so the in-memory blocklist
// picks up the new IPs immediately.
func New(db *storage.DB, reloadIPBL func()) *Worker {
	w := &Worker{
		db:         db,
		reloadIPBL: reloadIPBL,
		client:     &http.Client{Timeout: 30 * time.Second},
		ticker:     time.NewTicker(30 * time.Minute),
		stop:       make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *Worker) Stop() {
	w.once.Do(func() {
		w.ticker.Stop()
		close(w.stop)
	})
}

// SyncSource fetches a single source immediately (called from the UI sync-now button).
func (w *Worker) SyncSource(id int64) {
	sources, err := w.db.ListThreatIntelSources()
	if err != nil {
		return
	}
	for _, s := range sources {
		if s.ID == id {
			w.sync(s)
			return
		}
	}
}

func (w *Worker) run() {
	w.syncDue() // immediate first-pass on startup
	for {
		select {
		case <-w.ticker.C:
			w.syncDue()
		case <-w.stop:
			return
		}
	}
}

func (w *Worker) syncDue() {
	sources, err := w.db.ListThreatIntelSources()
	if err != nil {
		log.Printf("threat-intel: list sources: %v", err)
		return
	}
	now := time.Now()
	for _, s := range sources {
		if !s.Enabled {
			continue
		}
		deadline := s.LastSyncedAt.Add(time.Duration(s.IntervalHours) * time.Hour)
		if !s.LastSyncedAt.IsZero() && now.Before(deadline) {
			continue
		}
		w.sync(s)
	}
}

func (w *Worker) sync(s storage.ThreatIntelSource) {
	log.Printf("threat-intel: syncing %q (%s)", s.Label, s.URL)
	ips, err := fetchIPs(w.client, s.URL)
	if err != nil {
		log.Printf("threat-intel: %q fetch error: %v", s.Label, err)
		_ = w.db.UpdateThreatIntelSync(s.ID, 0, err.Error())
		return
	}
	if err := w.db.ReplaceThreatIntelIPs(s.ID, ips); err != nil {
		log.Printf("threat-intel: %q store error: %v", s.Label, err)
		_ = w.db.UpdateThreatIntelSync(s.ID, 0, err.Error())
		return
	}
	_ = w.db.UpdateThreatIntelSync(s.ID, len(ips), "")
	log.Printf("threat-intel: %q synced %d IPs", s.Label, len(ips))
	if w.reloadIPBL != nil {
		w.reloadIPBL()
	}
}

// fetchIPs downloads a plain-text IP block list, skipping comment lines
// (starting with '#' or ';') and returning only valid IP or CIDR tokens.
// A 10 MiB read limit guards against huge responses.
func fetchIPs(client *http.Client, url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "coraza-waf-mod/threat-intel")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	const maxBytes = 10 << 20 // 10 MiB
	var ips []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Take the first whitespace-delimited token so lines like "1.2.3.4 ; comment"
		// are handled correctly.
		token := strings.Fields(line)[0]
		if net.ParseIP(token) != nil {
			ips = append(ips, token)
		} else if _, _, err := net.ParseCIDR(token); err == nil {
			ips = append(ips, token)
		}
	}
	return ips, sc.Err()
}
