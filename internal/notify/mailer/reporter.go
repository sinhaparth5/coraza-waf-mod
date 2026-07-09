package mailer

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"coraza-waf-mod/internal/storage"
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
	if !cfg.Enabled || cfg.Token == "" || cfg.To == "" {
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

// SendBanAlert emails a notice that ip was automatically banned (autoban
// package). Silently skipped (nil) when email alerts are disabled or not
// fully configured — a ban must never depend on email being set up.
func (r *Reporter) SendBanAlert(ip, reason string) error {
	cfg, err := r.db.GetEmailConfig()
	if err != nil {
		return err
	}
	if !cfg.Enabled || cfg.Token == "" || cfg.To == "" {
		return nil
	}
	subject, text, html := composeBanAlert(ip, reason, r.now())
	return r.send(cfg, subject, text, html)
}

// fontStack mirrors the admin UI's typography (base.html); Plus Jakarta Sans
// is used when the recipient has it installed, otherwise the system fallback.
const fontStack = `'Plus Jakarta Sans',-apple-system,'Segoe UI',Arial,sans-serif`

// composeReport renders the plain-text and HTML bodies for one report window.
// The HTML mirrors the admin dashboard theme (canvas background, white
// rounded card, zebra-striped table with an uppercase header row) using only
// inline styles and nested tables — email clients ignore stylesheets, and
// Gmail strips SVG, so the logo badge is recreated as its three filter bars
// on the deep-green rounded square from static/imgs/logo.svg.
func composeReport(day string, rep storage.DailyReport) (subject, text, html string) {
	subject = fmt.Sprintf("WAF daily report %s — %d blocked, %d × 403, %d requests",
		day, rep.Blocked, rep.Status403, rep.Total)

	rows := []struct {
		label string
		value int
		alert bool // render in red when non-zero
	}{
		{"Total requests", rep.Total, false},
		{"Blocked requests", rep.Blocked, true},
		{"403 responses", rep.Status403, true},
		{"Unique blocked IPs", rep.UniqueBlockedIPs, false},
		{"WAF rule blocks", rep.WAFBlocked, false},
		{"IP blocklist blocks", rep.IPBlocked, false},
		{"Geo blocks", rep.GeoBlocked, false},
		{"Rate limited", rep.RateLimited, false},
		{"Bot challenges served", rep.BotChallenged, false},
	}

	var t strings.Builder
	fmt.Fprintf(&t, "Coraza WAF Mod — daily report for %s\n\n", day)
	for _, row := range rows {
		fmt.Fprintf(&t, "%-24s %d\n", row.label, row.value)
	}
	t.WriteString("\nSent automatically by Coraza WAF Mod.\n")

	var h strings.Builder
	// Canvas-colored backdrop, card centered inside.
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EAEBED"><tr><td align="center" style="padding:32px 12px">`)
	h.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;background:#ffffff;border:1px solid #EEF1F3;border-radius:28px">`)

	// Brand header: logo badge (deep-green rounded square + three filter bars) and full name.
	h.WriteString(`<tr><td style="padding:28px 32px 0">`)
	h.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0"><tr>`)
	h.WriteString(`<td width="40" height="40" align="center" style="width:40px;height:40px;background:#1a3d28;border-radius:10px;vertical-align:middle">`)
	h.WriteString(`<div style="width:22px;height:4px;background:#8edba8;border-radius:3px;margin:0 auto 3px"></div>`)
	h.WriteString(`<div style="width:17px;height:4px;background:#6cc98a;border-radius:3px;margin:0 auto 3px"></div>`)
	h.WriteString(`<div style="width:12px;height:4px;background:#4db872;border-radius:3px;margin:0 auto"></div>`)
	h.WriteString(`</td>`)
	h.WriteString(`<td style="padding-left:12px;vertical-align:middle">`)
	h.WriteString(`<p style="margin:0;font:700 16px ` + fontStack + `;color:#0f172a">Coraza WAF Mod</p>`)
	h.WriteString(`<p style="margin:2px 0 0;font:400 12px ` + fontStack + `;color:#64748b">Daily security report &middot; ` + day + `</p>`)
	h.WriteString(`</td></tr></table>`)
	h.WriteString(`</td></tr>`)

	// Metrics table, styled like the dashboard's request table.
	h.WriteString(`<tr><td style="padding:20px 32px 8px">`)
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">`)
	h.WriteString(`<tr>` +
		`<th align="left" style="padding:0 12px 10px;border-bottom:1px solid #EAEBED;font:600 11px ` + fontStack + `;color:#64748b;text-transform:uppercase;letter-spacing:.05em">Metric</th>` +
		`<th align="right" style="padding:0 12px 10px;border-bottom:1px solid #EAEBED;font:600 11px ` + fontStack + `;color:#64748b;text-transform:uppercase;letter-spacing:.05em">Count</th>` +
		`</tr>`)
	for i, row := range rows {
		bg := "#ffffff"
		if row.alert && row.value > 0 {
			bg = "#FEF2F2" // red-50, like blocked rows in the live logs table
		} else if i%2 == 1 {
			bg = "#F4F7F9" // surface, the dashboard's zebra stripe
		}
		valueColor := "#0f172a"
		if row.alert && row.value > 0 {
			valueColor = "#DC2626"
		}
		fmt.Fprintf(&h,
			`<tr style="background:%s">`+
				`<td style="padding:10px 12px;border-bottom:1px solid #F4F7F9;font:400 13px %s;color:#334155">%s</td>`+
				`<td align="right" style="padding:10px 12px;border-bottom:1px solid #F4F7F9;font:600 13px %s;color:%s">%d</td>`+
				`</tr>`,
			bg, fontStack, row.label, fontStack, valueColor, row.value)
	}
	h.WriteString(`</table>`)
	h.WriteString(`</td></tr>`)

	// Footer.
	h.WriteString(`<tr><td style="padding:8px 32px 28px">`)
	h.WriteString(`<p style="margin:0;font:400 12px ` + fontStack + `;color:#94A3B8">Sent automatically by Coraza WAF Mod from ` + Sender + `.</p>`)
	h.WriteString(`</td></tr>`)

	h.WriteString(`</table></td></tr></table>`)

	return subject, t.String(), h.String()
}

// composeBanAlert renders the notice sent when the autoban package bans an
// IP. Same visual language as the daily report: canvas backdrop, white
// rounded card, brand header, inline styles only.
func composeBanAlert(ip, reason string, at time.Time) (subject, text, html string) {
	subject = fmt.Sprintf("WAF banned IP %s", ip)
	when := at.Format("2006-01-02 15:04 MST")

	var t strings.Builder
	fmt.Fprintf(&t, "Coraza WAF Mod — automatic IP ban\n\n")
	fmt.Fprintf(&t, "IP address:  %s\n", ip)
	fmt.Fprintf(&t, "Reason:      %s\n", reason)
	fmt.Fprintf(&t, "Banned at:   %s\n", when)
	fmt.Fprintf(&t, "Scope:       Global (all services)\n\n")
	t.WriteString("The IP now appears on the IP Rules page, where the ban can be lifted.\n")

	rows := []struct{ label, value string }{
		{"IP address", ip},
		{"Reason", reason},
		{"Banned at", when},
		{"Scope", "Global (all services)"},
	}

	var h strings.Builder
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EAEBED"><tr><td align="center" style="padding:32px 12px">`)
	h.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;background:#ffffff;border:1px solid #EEF1F3;border-radius:28px">`)

	// Brand header: logo badge (deep-green rounded square + three filter bars) and full name.
	h.WriteString(`<tr><td style="padding:28px 32px 0">`)
	h.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0"><tr>`)
	h.WriteString(`<td width="40" height="40" align="center" style="width:40px;height:40px;background:#1a3d28;border-radius:10px;vertical-align:middle">`)
	h.WriteString(`<div style="width:22px;height:4px;background:#8edba8;border-radius:3px;margin:0 auto 3px"></div>`)
	h.WriteString(`<div style="width:17px;height:4px;background:#6cc98a;border-radius:3px;margin:0 auto 3px"></div>`)
	h.WriteString(`<div style="width:12px;height:4px;background:#4db872;border-radius:3px;margin:0 auto"></div>`)
	h.WriteString(`</td>`)
	h.WriteString(`<td style="padding-left:12px;vertical-align:middle">`)
	h.WriteString(`<p style="margin:0;font:700 16px ` + fontStack + `;color:#0f172a">Coraza WAF Mod</p>`)
	h.WriteString(`<p style="margin:2px 0 0;font:400 12px ` + fontStack + `;color:#64748b">Automatic IP ban</p>`)
	h.WriteString(`</td></tr></table>`)
	h.WriteString(`</td></tr>`)

	// Red alert banner with the banned IP.
	h.WriteString(`<tr><td style="padding:20px 32px 0">`)
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#FEF2F2;border:1px solid #FECACA;border-radius:14px"><tr><td style="padding:14px 18px">`)
	h.WriteString(`<p style="margin:0;font:600 11px ` + fontStack + `;color:#DC2626;text-transform:uppercase;letter-spacing:.05em">IP address banned</p>`)
	h.WriteString(`<p style="margin:4px 0 0;font:700 20px 'SF Mono',Consolas,monospace;color:#0f172a">` + ip + `</p>`)
	h.WriteString(`</td></tr></table>`)
	h.WriteString(`</td></tr>`)

	// Detail rows, styled like the daily report's metric table.
	h.WriteString(`<tr><td style="padding:16px 32px 8px">`)
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">`)
	for i, row := range rows {
		bg := "#ffffff"
		if i%2 == 1 {
			bg = "#F4F7F9"
		}
		fmt.Fprintf(&h,
			`<tr style="background:%s">`+
				`<td style="padding:10px 12px;border-bottom:1px solid #F4F7F9;font:400 13px %s;color:#64748b;white-space:nowrap">%s</td>`+
				`<td style="padding:10px 12px;border-bottom:1px solid #F4F7F9;font:600 13px %s;color:#334155">%s</td>`+
				`</tr>`,
			bg, fontStack, row.label, fontStack, row.value)
	}
	h.WriteString(`</table>`)
	h.WriteString(`</td></tr>`)

	// Footer.
	h.WriteString(`<tr><td style="padding:8px 32px 28px">`)
	h.WriteString(`<p style="margin:0;font:400 12px ` + fontStack + `;color:#94A3B8">The ban is a global block rule on the IP Rules page — remove it there to lift it. Sent automatically by Coraza WAF Mod from ` + Sender + `.</p>`)
	h.WriteString(`</td></tr>`)

	h.WriteString(`</table></td></tr></table>`)

	return subject, t.String(), h.String()
}
