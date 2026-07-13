package mailer

import (
	"errors"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/internal/storage"
)

// fakeStore satisfies the store interface without a database.
type fakeStore struct {
	cfg     storage.EmailConfig
	report  storage.DailyReport
	sentFor string
	// window the reporter asked for, captured for assertions
	from, to time.Time
}

func (f *fakeStore) GetEmailConfig() (storage.EmailConfig, error) { return f.cfg, nil }
func (f *fakeStore) GetDailyReport(from, to time.Time) (storage.DailyReport, error) {
	f.from, f.to = from, to
	return f.report, nil
}
func (f *fakeStore) GetEmailReportSentFor() (string, error) { return f.sentFor, nil }
func (f *fakeStore) SetEmailReportSentFor(day string) error { f.sentFor = day; return nil }

func enabledConfig() storage.EmailConfig {
	return storage.EmailConfig{Enabled: true, Token: "secret", To: "ops@example.com"}
}

// testReporter returns a Reporter with a captured send func and a fixed clock,
// without starting the scheduler goroutine.
func testReporter(db *fakeStore, now time.Time) (*Reporter, *[]string) {
	var subjects []string
	r := &Reporter{
		db:   db,
		stop: make(chan struct{}),
		now:  func() time.Time { return now },
		send: func(_ storage.EmailConfig, subject, _, _ string) error {
			subjects = append(subjects, subject)
			return nil
		},
	}
	return r, &subjects
}

func TestMaybeSendDailySendsOncePerDay(t *testing.T) {
	db := &fakeStore{cfg: enabledConfig(), report: storage.DailyReport{Total: 100, Blocked: 7, Status403: 5}}
	now := time.Date(2026, 7, 2, 0, 1, 0, 0, time.UTC)
	r, subjects := testReporter(db, now)

	r.maybeSendDaily()
	if len(*subjects) != 1 {
		t.Fatalf("sent %d reports, want 1", len(*subjects))
	}
	if db.sentFor != "2026-07-01" {
		t.Errorf("marked sent for %q, want 2026-07-01 (the completed day)", db.sentFor)
	}
	// Window must be exactly the previous local day.
	wantFrom := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)
	if !db.from.Equal(wantFrom) || !db.to.Equal(wantTo) {
		t.Errorf("report window [%v, %v), want [%v, %v)", db.from, db.to, wantFrom, wantTo)
	}

	// Second tick the same day (e.g. after a restart): guarded, no duplicate.
	r.maybeSendDaily()
	if len(*subjects) != 1 {
		t.Fatalf("restart re-sent the report: %d sends, want 1", len(*subjects))
	}
}

func TestMaybeSendDailySkipsWhenDisabledOrIncomplete(t *testing.T) {
	for name, mutate := range map[string]func(*storage.EmailConfig){
		"disabled": func(c *storage.EmailConfig) { c.Enabled = false },
		"no token": func(c *storage.EmailConfig) { c.Token = "" },
		"no to":    func(c *storage.EmailConfig) { c.To = "" },
	} {
		cfg := enabledConfig()
		mutate(&cfg)
		db := &fakeStore{cfg: cfg}
		r, subjects := testReporter(db, time.Date(2026, 7, 2, 0, 1, 0, 0, time.UTC))
		r.maybeSendDaily()
		if len(*subjects) != 0 {
			t.Errorf("%s: report was sent, want skip", name)
		}
		if db.sentFor != "" {
			t.Errorf("%s: skip must not mark the day as sent", name)
		}
	}
}

func TestMaybeSendDailyRetriesAfterFailure(t *testing.T) {
	db := &fakeStore{cfg: enabledConfig()}
	now := time.Date(2026, 7, 2, 0, 1, 0, 0, time.UTC)
	r, _ := testReporter(db, now)
	sends := 0
	r.send = func(storage.EmailConfig, string, string, string) error {
		sends++
		if sends == 1 {
			return errors.New("smtp unreachable")
		}
		return nil
	}

	r.maybeSendDaily()
	if db.sentFor != "" {
		t.Fatal("failed send must not mark the day as sent")
	}
	r.maybeSendDaily() // e.g. restart later the same day
	if sends != 2 || db.sentFor != "2026-07-01" {
		t.Fatalf("after retry: sends=%d sentFor=%q, want 2 and 2026-07-01", sends, db.sentFor)
	}
}

func TestSendNowWorksWhileDisabled(t *testing.T) {
	cfg := enabledConfig()
	cfg.Enabled = false // testing credentials before turning the schedule on
	db := &fakeStore{cfg: cfg, report: storage.DailyReport{Total: 3}}
	r, subjects := testReporter(db, time.Date(2026, 7, 2, 15, 0, 0, 0, time.UTC))

	if err := r.SendNow(); err != nil {
		t.Fatalf("SendNow: %v", err)
	}
	if len(*subjects) != 1 {
		t.Fatalf("sent %d reports, want 1", len(*subjects))
	}
	if got := db.to.Sub(db.from); got != 24*time.Hour {
		t.Errorf("SendNow window = %v, want 24h", got)
	}
}

func TestSendBanAlertGatedOnEnabledConfig(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

	// Fully configured: one alert goes out, subject names the IP.
	db := &fakeStore{cfg: enabledConfig()}
	r, subjects := testReporter(db, now)
	if err := r.SendBanAlert("203.0.113.7", "12 blocked requests in 10 min"); err != nil {
		t.Fatalf("SendBanAlert: %v", err)
	}
	if len(*subjects) != 1 || !strings.Contains((*subjects)[0], "203.0.113.7") {
		t.Fatalf("subjects = %v, want one alert naming the IP", *subjects)
	}

	// Disabled or incomplete config: skipped silently, no error.
	for name, mutate := range map[string]func(*storage.EmailConfig){
		"disabled": func(c *storage.EmailConfig) { c.Enabled = false },
		"no token": func(c *storage.EmailConfig) { c.Token = "" },
		"no to":    func(c *storage.EmailConfig) { c.To = "" },
	} {
		cfg := enabledConfig()
		mutate(&cfg)
		r, subjects := testReporter(&fakeStore{cfg: cfg}, now)
		if err := r.SendBanAlert("203.0.113.7", "reason"); err != nil {
			t.Errorf("%s: SendBanAlert returned error %v, want silent skip", name, err)
		}
		if len(*subjects) != 0 {
			t.Errorf("%s: alert sent despite incomplete config", name)
		}
	}
}

func TestComposeBanAlertIncludesIPAndReason(t *testing.T) {
	at := time.Date(2026, 7, 2, 3, 4, 0, 0, time.UTC)
	subject, text, html := composeBanAlert("203.0.113.7", "2 critical WAF hits in 10 min", at)
	if !strings.Contains(subject, "203.0.113.7") {
		t.Errorf("subject missing IP: %q", subject)
	}
	for _, body := range []string{text, html} {
		for _, want := range []string{"203.0.113.7", "2 critical WAF hits in 10 min", "IP Rules"} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
		}
	}
}

func TestComposeReportIncludesCounts(t *testing.T) {
	subject, text, html := composeReport("2026-07-01", storage.DailyReport{
		Total: 1234, Blocked: 56, Status403: 44, UniqueBlockedIPs: 9,
		WAFBlocked: 20, IPBlocked: 15, GeoBlocked: 10, RateLimited: 11, BotChallenged: 3,
	})
	if !strings.Contains(subject, "56 blocked") || !strings.Contains(subject, "44 × 403") {
		t.Errorf("subject missing headline counts: %q", subject)
	}
	for _, body := range []string{text, html} {
		for _, want := range []string{"1234", "56", "44", "9", "2026-07-01"} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
		}
	}
}

func TestUntilNextMidnight(t *testing.T) {
	now := time.Date(2026, 7, 2, 23, 0, 0, 0, time.UTC)
	got := untilNextMidnight(now)
	if got != time.Hour+time.Minute {
		t.Errorf("untilNextMidnight = %v, want 1h1m (1h to midnight + 1m pad)", got)
	}
}

func TestFromHeaderCarriesDisplayName(t *testing.T) {
	msg := string(buildMessage(fromHeader(), []string{"b@y.com"}, "Subj", "text", "<p>html</p>"))
	want := "From: Coraza WAF Mod <alert@astrareconslabs.com>\r\n"
	if !strings.Contains(msg, want) {
		t.Errorf("message missing %q — Gmail would show the bare address", want)
	}
}

func TestBuildMessageIsWellFormedMIME(t *testing.T) {
	msg := string(buildMessage("a@x.com", []string{"b@y.com", "c@z.com"}, "Subj", "plain\nbody", "<p>html</p>"))

	for _, want := range []string{
		"From: a@x.com\r\n",
		"To: b@y.com, c@z.com\r\n",
		"Subject: Subj\r\n",
		"MIME-Version: 1.0\r\n",
		`Content-Type: multipart/alternative; boundary="`,
		"plain\r\nbody",
		"<p>html</p>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q", want)
		}
	}
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Error("message contains bare LF line endings")
	}
}

// TestSendLoginCodeRequiresTokenAndRecipient checks the 2FA recovery email:
// it must send even with the Enabled toggle off (the admin explicitly asked
// for it), but must error — not silently skip — when the mailer has no
// token or recipient to send with.
func TestSendLoginCodeRequiresTokenAndRecipient(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

	cfg := enabledConfig()
	cfg.Enabled = false // reports/alerts off must not block explicit recovery
	r, subjects := testReporter(&fakeStore{cfg: cfg}, now)
	if err := r.SendLoginCode("482913"); err != nil {
		t.Fatalf("SendLoginCode with Enabled=false: %v", err)
	}
	if len(*subjects) != 1 {
		t.Fatalf("subjects = %v, want one login-code mail", *subjects)
	}

	for name, mutate := range map[string]func(*storage.EmailConfig){
		"no token": func(c *storage.EmailConfig) { c.Token = "" },
		"no to":    func(c *storage.EmailConfig) { c.To = "" },
	} {
		cfg := enabledConfig()
		mutate(&cfg)
		r, subjects := testReporter(&fakeStore{cfg: cfg}, now)
		if err := r.SendLoginCode("482913"); err == nil {
			t.Errorf("%s: SendLoginCode returned nil, want error", name)
		}
		if len(*subjects) != 0 {
			t.Errorf("%s: mail sent despite incomplete config", name)
		}
	}
}

// TestComposeLoginCodeBody checks the code lands in both bodies and the
// plain-text body carries the expiry warning.
func TestComposeLoginCodeBody(t *testing.T) {
	_, text, html := composeLoginCode("482913", time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC))
	if !strings.Contains(text, "482913") || !strings.Contains(html, "482913") {
		t.Error("code missing from a body")
	}
	if !strings.Contains(text, "expires in 10 minutes") {
		t.Error("plain-text body missing expiry note")
	}
}
