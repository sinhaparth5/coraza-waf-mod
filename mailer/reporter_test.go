package mailer

import (
	"errors"
	"strings"
	"testing"
	"time"

	"coraza-waf-mod/storage"
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
	return storage.EmailConfig{
		Enabled: true, Host: "smtp.example.com", Port: 465,
		Username: "api_token", Token: "secret",
		From: "alert@example.com", To: "ops@example.com",
	}
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
		"no from":  func(c *storage.EmailConfig) { c.From = "" },
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
