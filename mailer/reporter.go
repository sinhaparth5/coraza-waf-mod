package mailer

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/storage"
)

// store is the slice of *storage.DB the reporter needs; an interface so tests
// can run without a real database.
type store interface {
	GetEmailConfig() (storage.EmailConfig, error)
	GetDailyReport(from, to time.Time) (storage.DailyReport, error)
	GetEmailReportSentFor() (string, error)
	SetEmailReportSentFor(day string) error
}

// Reporter emails a summary of the previous day's traffic shortly after local
// midnight. Config is read from the DB on every run, so enabling or changing
// credentials in the admin UI takes effect without a restart. The
// "email_report_sent_for" meta key makes sends idempotent per day: a restart
// right after midnight (or downtime across midnight) neither duplicates nor
// permanently skips a report.
type Reporter struct {
	db   store
	stop chan struct{}
	once sync.Once
	now  func() time.Time                                        // injectable for tests
	send func(storage.EmailConfig, string, string, string) error // injectable for tests
}

// NewReporter starts the background scheduler goroutine.
func NewReporter(db *storage.DB) *Reporter {
	r := &Reporter{db: db, stop: make(chan struct{}), now: time.Now, send: Send}
	go r.run()
	return r
}

// Stop shuts down the scheduler goroutine.
func (r *Reporter) Stop() { r.once.Do(func() { close(r.stop) }) }

func (r *Reporter) run() {
	for {
		// Runs once at startup (catching up a report missed while the server
		// was down over midnight) and then once after each midnight.
		r.maybeSendDaily()
		select {
		case <-time.After(untilNextMidnight(r.now())):
		case <-r.stop:
			return
		}
	}
}

// untilNextMidnight returns the wait until just past the next local midnight;
// the one-minute pad keeps clock skew from firing inside the old day.
func untilNextMidnight(now time.Time) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, 1)
	return next.Sub(now) + time.Minute
}

// maybeSendDaily sends the report for the most recently completed local day,
// unless alerts are disabled or that day's report already went out.
func (r *Reporter) maybeSendDaily() {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		log.Printf("mailer: read config: %v", err)
		return
	}
	if !cfg.Enabled || cfg.Token == "" || cfg.To == "" || cfg.From == "" {
		return
	}

	now := r.now()
	dayEnd := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	dayStart := dayEnd.AddDate(0, 0, -1)
	day := dayStart.Format("2006-01-02")

	if sentFor, err := r.db.GetEmailReportSentFor(); err == nil && sentFor == day {
		return
	}
	rep, err := r.db.GetDailyReport(dayStart, dayEnd)
	if err != nil {
		log.Printf("mailer: daily report query: %v", err)
		return
	}

	subject, text, html := composeReport(day, rep)
	if err := r.send(cfg, subject, text, html); err != nil {
		// Not marked as sent — the next midnight tick (or a restart) retries.
		log.Printf("mailer: daily report for %s failed: %v", day, err)
		return
	}
	if err := r.db.SetEmailReportSentFor(day); err != nil {
		log.Printf("mailer: mark report sent: %v", err)
	}
	log.Printf("mailer: daily report for %s sent to %s", day, cfg.To)
}

// SendNow emails a report covering the last 24 hours immediately, regardless
// of the enabled flag (so credentials can be verified before turning the
// schedule on). Used by the admin UI's "send test report" button.
func (r *Reporter) SendNow() error {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		return err
	}
	now := r.now()
	rep, err := r.db.GetDailyReport(now.Add(-24*time.Hour), now)
	if err != nil {
		return err
	}
	subject, text, html := composeReport(now.Format("2006-01-02")+" (last 24 h)", rep)
	return r.send(cfg, subject, text, html)
}

// composeReport renders the plain-text and HTML bodies for one report window.
// HTML styling is inline (email clients ignore stylesheets).
func composeReport(day string, rep storage.DailyReport) (subject, text, html string) {
	subject = fmt.Sprintf("WAF daily report %s — %d blocked, %d × 403, %d requests",
		day, rep.Blocked, rep.Status403, rep.Total)

	rows := []struct {
		label string
		value int
	}{
		{"Total requests", rep.Total},
		{"Blocked requests", rep.Blocked},
		{"403 responses", rep.Status403},
		{"Unique blocked IPs", rep.UniqueBlockedIPs},
		{"WAF rule blocks", rep.WAFBlocked},
		{"IP blocklist blocks", rep.IPBlocked},
		{"Geo blocks", rep.GeoBlocked},
		{"Rate limited", rep.RateLimited},
		{"Bot challenges served", rep.BotChallenged},
	}

	var t strings.Builder
	fmt.Fprintf(&t, "Coraza WAF Mod — daily report for %s\n\n", day)
	for _, row := range rows {
		fmt.Fprintf(&t, "%-24s %d\n", row.label, row.value)
	}
	t.WriteString("\nSent automatically by Coraza WAF Mod.\n")

	var h strings.Builder
	h.WriteString(`<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;color:#1e293b">`)
	h.WriteString(`<h2 style="font-size:18px;margin:24px 0 4px">Coraza WAF Mod — daily report</h2>`)
	h.WriteString(`<p style="font-size:13px;color:#64748b;margin:0 0 16px">` + day + `</p>`)
	h.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
	for i, row := range rows {
		bg := "#ffffff"
		if i%2 == 0 {
			bg = "#f4f7f9"
		}
		fmt.Fprintf(&h,
			`<tr style="background:%s"><td style="padding:8px 12px;border:1px solid #e2e5ea">%s</td>`+
				`<td style="padding:8px 12px;border:1px solid #e2e5ea;text-align:right;font-weight:600">%d</td></tr>`,
			bg, row.label, row.value)
	}
	h.WriteString(`</table>`)
	h.WriteString(`<p style="font-size:12px;color:#94a3b8;margin-top:16px">Sent automatically by Coraza WAF Mod.</p>`)
	h.WriteString(`</div>`)

	return subject, t.String(), h.String()
}
