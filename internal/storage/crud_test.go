package storage

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"palisade/internal/security/ratelimit"
)

// These tests exercise the plain CRUD/query methods the admin UI relies on.
// Like every test here they go through openTestDB, so CI reruns them against
// MySQL and Postgres — the point is as much "this SQL is portable" as
// "this method works".

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func serviceByName(t *testing.T, db *DB, name string) Service {
	t.Helper()
	svcs, err := db.ListServices()
	mustNoErr(t, err)
	for _, s := range svcs {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("service %q not found", name)
	return Service{}
}

func TestServiceMutations(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.AddService("shop", "shop.test", "", "http://10.0.0.1", 0, 0))
	id := serviceByName(t, db, "shop").ID

	mustNoErr(t, db.UpdateService(id, "store", "store.test", "/s", "http://10.0.0.2"))
	mustNoErr(t, db.SetServiceRateLimit(id, 2.5, 7))
	mustNoErr(t, db.SetServiceBotMode(id, "always"))
	mustNoErr(t, db.SetServiceCacheSession(id, true, "sid"))
	mustNoErr(t, db.SetServiceCacheTuning(id, 1, 2, 3, 4))
	mustNoErr(t, db.SetServiceTLS(id, "custom", "/c.pem", "/k.pem", "2030-01-01T00:00:00Z"))

	s, err := db.GetService(id)
	mustNoErr(t, err)
	if s.Name != "store" || s.Host != "store.test" || s.Prefix != "/s" || s.Backend != "http://10.0.0.2" ||
		s.RateLimitRPS != 2.5 || s.RateLimitBurst != 7 || s.BotMode != "always" ||
		!s.CacheBySession || s.SessionCookieName != "sid" ||
		s.CacheTTLFloor != 1 || s.CacheTTLCeiling != 2 || s.CacheGrace != 3 || s.CacheKeep != 4 || s.TLSMode != "custom" {
		t.Fatalf("service = %+v", s)
	}

	certID, err := db.AddCertificate("pool", "store.test", "2030-01-01T00:00:00Z", "", "")
	mustNoErr(t, err)
	mustNoErr(t, db.UpdateCertificatePaths(certID, "/pool/c.pem", "/pool/k.pem"))
	mustNoErr(t, db.SetServiceCertID(id, certID))
	c, err := db.GetCertificate(certID)
	mustNoErr(t, err)
	if c.CertPath != "/pool/c.pem" || c.KeyPath != "/pool/k.pem" {
		t.Fatalf("cert = %+v", c)
	}
	if s, _ := db.GetService(id); s.CertID != certID {
		t.Fatalf("cert id = %d", s.CertID)
	}
	// Deleting a pool cert detaches it from the services using it.
	mustNoErr(t, db.DeleteCertificate(certID))
	if s, _ := db.GetService(id); s.CertID != 0 {
		t.Errorf("cert still attached after delete: %+v", s)
	}
	if _, err := db.GetCertificate(certID); err == nil {
		t.Error("deleted cert still readable")
	}

	mustNoErr(t, db.ClearServiceTLS(id))
	if s, _ := db.GetService(id); s.TLSMode != "" && s.TLSMode != "none" {
		t.Errorf("tls mode after clear = %q", s.TLSMode)
	}
	mustNoErr(t, db.RemoveService(id))
	if svcs, _ := db.ListServices(); len(svcs) != 0 {
		t.Error("service not removed")
	}
}

func TestMigrateConfigAppsRunsOnce(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.MigrateConfigApps([]ConfigApp{{Name: "a", Host: "a.test", Backend: "http://10.0.0.1"}}))
	mustNoErr(t, db.MigrateConfigApps([]ConfigApp{{Name: "b", Host: "b.test", Backend: "http://10.0.0.2"}}))
	if svcs, _ := db.ListServices(); len(svcs) != 1 || svcs[0].Name != "a" {
		t.Fatalf("services = %+v", svcs)
	}
}

func TestRuleRemoval(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.AddIPRule("", "1.2.3.4", "block"))
	mustNoErr(t, db.AddGeoRule("", "CN", "block"))
	ips, _ := db.ListIPRules()
	geos, _ := db.ListGeoRules()
	if len(ips) != 1 || len(geos) != 1 || geos[0].CountryCode != "CN" {
		t.Fatalf("ips=%+v geos=%+v", ips, geos)
	}
	mustNoErr(t, db.RemoveIPRule(ips[0].ID))
	mustNoErr(t, db.RemoveGeoRule(geos[0].ID))
	ips, _ = db.ListIPRules()
	geos, _ = db.ListGeoRules()
	if len(ips)+len(geos) != 0 {
		t.Error("rules not removed")
	}

	mustNoErr(t, db.DisableWAFRule(942100, "fp"))
	dis, _ := db.ListDisabledWAFRules()
	if len(dis) != 1 || dis[0].RuleID != 942100 {
		t.Fatalf("disabled = %+v", dis)
	}
	mustNoErr(t, db.EnableWAFRule(dis[0].ID))
	if dis, _ := db.ListDisabledWAFRules(); len(dis) != 0 {
		t.Error("rule not re-enabled")
	}
}

func TestMetaBackedSettings(t *testing.T) {
	db := openTestDB(t)

	if en, th, ttl, err := db.GetBotSettings(); err != nil || en || th <= 0 || ttl <= 0 {
		t.Fatalf("bot defaults = %v %d %d %v", en, th, ttl, err)
	}
	mustNoErr(t, db.SetBotSettings(true, 5, 60))
	if en, th, ttl, _ := db.GetBotSettings(); !en || th != 5 || ttl != 60 {
		t.Errorf("bot = %v %d %d", en, th, ttl)
	}

	mustNoErr(t, db.SetAcmeEmail("ops@x.test"))
	mustNoErr(t, db.SetPrimaryDomain("x.test"))
	mustNoErr(t, db.SetEmailReportSentFor("2026-10-14"))
	for name, get := range map[string]func() (string, error){
		"ops@x.test": db.GetAcmeEmail, "x.test": db.GetPrimaryDomain, "2026-10-14": db.GetEmailReportSentFor,
	} {
		if got, err := get(); err != nil || got != name {
			t.Errorf("meta %q = %q %v", name, got, err)
		}
	}

	mustNoErr(t, db.SetTypeSafeConfig(TypeSafeConfig{Enabled: true, APIKey: "k"}))
	if tc, _ := db.GetTypeSafeConfig(); !tc.Enabled || tc.APIKey != "k" {
		t.Errorf("typesafe = %+v", tc)
	}

	// First read initializes to now, so a fresh install has no backlog badge.
	seen, err := db.NotificationsSeenAt()
	mustNoErr(t, err)
	if time.Since(seen) > time.Minute {
		t.Errorf("seen on first read = %v", seen)
	}
	mustNoErr(t, db.MarkNotificationsSeen())
	if seen, _ := db.NotificationsSeenAt(); time.Since(seen) > time.Minute {
		t.Errorf("seen after mark = %v", seen)
	}
}

func TestAdminCredentials(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.SeedAdmin("a@x.test", "first-password"))
	mustNoErr(t, db.SeedAdmin("b@x.test", "second-password")) // idempotent: keeps the first
	if ok, _ := db.CheckAdminPassword("first-password"); !ok {
		t.Fatal("seeded password rejected")
	}
	if ok, _ := db.CheckAdminPassword("second-password"); ok {
		t.Fatal("re-seed overwrote the password")
	}
	mustNoErr(t, db.UpdateAdminCredentials("", "third-password")) // blank email keeps it
	if email, _ := db.GetAdminEmail(); email != "a@x.test" {
		t.Errorf("email = %q", email)
	}
	mustNoErr(t, db.UpdateAdminCredentials("c@x.test", "")) // blank password keeps it
	if ok, _ := db.CheckAdminPassword("third-password"); !ok {
		t.Error("password lost on email-only change")
	}
	if email, _ := db.GetAdminEmail(); email != "c@x.test" {
		t.Errorf("email = %q", email)
	}
}

func TestWebAuthnCredentials(t *testing.T) {
	db := openTestDB(t)
	h1, err := db.GetOrCreateWebAuthnHandle()
	mustNoErr(t, err)
	h2, _ := db.GetOrCreateWebAuthnHandle()
	if len(h1) == 0 || string(h1) != string(h2) {
		t.Fatal("handle not stable")
	}
	if en, _ := db.WebAuthnEnabled(); en {
		t.Fatal("enabled with no credentials")
	}
	mustNoErr(t, db.AddWebAuthnCredential("cred1", "Key", []byte(`{"v":1}`)))
	mustNoErr(t, db.TouchWebAuthnCredential("cred1", []byte(`{"v":2}`)))
	creds, _ := db.ListWebAuthnCredentials()
	if len(creds) != 1 || string(creds[0].Data) != `{"v":2}` {
		t.Fatalf("creds = %+v", creds)
	}
	if en, _ := db.WebAuthnEnabled(); !en {
		t.Fatal("not enabled with a credential")
	}
	mustNoErr(t, db.DeleteWebAuthnCredential(creds[0].ID))
	if en, _ := db.WebAuthnEnabled(); en {
		t.Error("still enabled after delete")
	}
}

func TestSessionLifecycle(t *testing.T) {
	db := openTestDB(t)
	tok, err := db.CreateSession("10.0.0.1", "ua", "dev")
	mustNoErr(t, err)
	mustNoErr(t, db.TouchSession(tok))
	mustNoErr(t, db.RevokeSession(tok))
	if s, _ := db.GetSession(tok); s == nil || !s.Revoked() {
		t.Fatalf("revoked session = %+v", s)
	}
	mustNoErr(t, db.DeleteSession(tok))
	if s, _ := db.GetSession(tok); s != nil {
		t.Error("session not deleted")
	}
}

func TestRateLimitStateRoundTrip(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	mustNoErr(t, db.SaveRateLimitState([]ratelimit.BucketState{
		{IP: "1.1.1.1", Tokens: 3, LastRefill: now},
		{IP: "2.2.2.2", Tokens: 1, LastRefill: now.Add(-time.Hour)},
	}))
	mustNoErr(t, db.PurgeRateLimitState(now.Add(-time.Minute)))
	states, err := db.LoadRateLimitState()
	mustNoErr(t, err)
	if len(states) != 1 || states[0].IP != "1.1.1.1" || states[0].Tokens != 3 || !states[0].LastRefill.Equal(now) {
		t.Fatalf("states = %+v", states)
	}
	// Each save replaces the whole table.
	mustNoErr(t, db.SaveRateLimitState(nil))
	if states, _ := db.LoadRateLimitState(); len(states) != 0 {
		t.Fatalf("states after empty save = %+v", states)
	}
}

func TestThreatIntelStore(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.AddThreatIntelSource("feed", "https://x.test/l", 6))
	srcs, _ := db.ListThreatIntelSources()
	if len(srcs) != 1 || !srcs[0].Enabled || !srcs[0].LastSyncedAt.IsZero() {
		t.Fatalf("sources = %+v", srcs)
	}
	id := srcs[0].ID
	mustNoErr(t, db.ReplaceThreatIntelIPs(id, []string{"1.2.3.4", "10.0.0.0/8"}))
	mustNoErr(t, db.ReplaceThreatIntelIPs(id, []string{"5.6.7.8"}))
	mustNoErr(t, db.UpdateThreatIntelSync(id, 1, ""))
	mustNoErr(t, db.UpdateThreatIntelSync(id, 0, "boom")) // a failed sync keeps the last good count
	if ips, _ := db.ListThreatIntelIPs(); len(ips) != 1 || ips[0] != "5.6.7.8" {
		t.Errorf("ips = %v (replace should drop the old list)", ips)
	}
	mustNoErr(t, db.SetThreatIntelSourceEnabled(id, false))
	srcs, _ = db.ListThreatIntelSources()
	if srcs[0].Enabled || srcs[0].IPCount != 1 || srcs[0].LastError != "boom" || srcs[0].LastSyncedAt.IsZero() {
		t.Fatalf("source = %+v", srcs[0])
	}
	if ips, _ := db.ListThreatIntelIPs(); len(ips) != 0 {
		t.Errorf("disabled source still contributes IPs: %v", ips)
	}
	mustNoErr(t, db.SetThreatIntelSourceEnabled(id, true))
	mustNoErr(t, db.DeleteThreatIntelSource(id))
	if ips, _ := db.ListThreatIntelIPs(); len(ips) != 0 {
		t.Errorf("ips survive source delete: %v", ips)
	}
}

func TestRequestQueries(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	insert := func(r RequestLog) {
		t.Helper()
		if r.Timestamp.IsZero() {
			r.Timestamp = now
		}
		_, err := db.InsertRequest(r)
		mustNoErr(t, err)
	}
	insert(RequestLog{AppName: "a", RealIP: "1.1.1.1", Country: "CN", Method: "GET", Path: "/x", Status: 403, Blocked: true, RuleID: 942100, Action: "deny", Duration: 10, VisitorID: "v1"})
	insert(RequestLog{AppName: "a", RealIP: "1.1.1.1", Country: "CN", Method: "GET", Path: "/y", Status: 403, Blocked: true, RuleID: 942100, Action: "deny", Duration: 20})
	insert(RequestLog{AppName: "a", RealIP: "2.2.2.2", Country: "US", Method: "POST", Path: "/", Status: 200, Duration: 30, VisitorID: "v2", Query: "a=1", Host: "a.test"})
	insert(RequestLog{AppName: "b", RealIP: "3.3.3.3", Country: "US", Method: "GET", Path: "/c", Status: 307, Action: "bot_challenge:adaptive"})
	insert(RequestLog{AppName: "b", RealIP: "4.4.4.4", Country: "DE", Method: "GET", Path: "/old", Status: 500, Timestamp: now.Add(-48 * time.Hour)})

	stats, err := db.GetStats()
	mustNoErr(t, err)
	if stats.TotalAll != 5 || stats.BlockedAll != 2 || stats.TotalToday < 4 || stats.BlockedToday != 2 {
		t.Errorf("stats = %+v", stats)
	}
	if bs := db.GetBotStats(); bs.ChallengedToday != 1 {
		t.Errorf("bot stats = %+v", bs)
	}
	ag, err := db.GetAtAGlanceStats()
	mustNoErr(t, err)
	if ag.RequestsLastMinute != 4 || ag.BlockedLastMinute != 2 || ag.WAFRuleHitsToday != 2 || ag.UniqueVisitorsToday != 2 || ag.AvgLatencyMS != 15 {
		t.Errorf("at a glance = %+v", ag)
	}

	if rows, _ := db.ListRequests(true, "", 10, 0); len(rows) != 2 {
		t.Errorf("blocked rows = %d", len(rows))
	}
	if rows, _ := db.ListRequests(false, "2.2.2.2", 10, 0); len(rows) != 1 || rows[0].Method != "POST" {
		t.Errorf("rows by ip = %+v", rows)
	}

	for _, tc := range []struct {
		f    LogFilter
		want int
	}{
		{LogFilter{Limit: 10}, 5},
		{LogFilter{AppName: "b", Limit: 10}, 2},
		{LogFilter{StatusClass: "2xx", Limit: 10}, 1},
		{LogFilter{StatusClass: "3xx", Limit: 10}, 1},
		{LogFilter{StatusClass: "4xx", Limit: 10}, 2},
		{LogFilter{StatusClass: "5xx", Limit: 10}, 1},
		{LogFilter{StatusClass: "blocked", Limit: 10}, 2},
		{LogFilter{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: 10}, 4},
		{LogFilter{Limit: 2, Offset: 4}, 5},
	} {
		rows, total, err := db.ListRequestsFiltered(tc.f)
		mustNoErr(t, err)
		if total != tc.want || len(rows) > tc.f.Limit {
			t.Errorf("filter %+v: total=%d rows=%d want total %d", tc.f, total, len(rows), tc.want)
		}
	}

	pts, err := db.GetHourlyTraffic(24)
	mustNoErr(t, err)
	sum := 0
	for _, p := range pts {
		sum += p.Total
	}
	if sum != 4 {
		t.Errorf("hourly total = %d (%+v)", sum, pts)
	}
	if top, _ := db.GetTopCountries(5, 24); len(top) != 2 || top[0].Country != "CN" && top[0].Country != "US" {
		t.Errorf("top countries = %+v", top)
	}
	if top, _ := db.GetTopBlockedCountries(5, 24); len(top) != 1 || top[0].Country != "CN" || top[0].Count != 2 {
		t.Errorf("top blocked countries = %+v", top)
	}
	if n, _ := db.CountBlockedSince(now.Add(-time.Hour)); n != 2 {
		t.Errorf("blocked since = %d", n)
	}
	mustNoErr(t, db.DisableWAFRule(942100, ""))
	if hits, _ := db.GetTopFiringRules(5); len(hits) != 1 || hits[0].RuleID != 942100 || hits[0].HitCount != 2 || !hits[0].Disabled {
		t.Errorf("top rules = %+v", hits)
	}
	if replay, _ := db.ListReplayRequests(10); len(replay) == 0 {
		t.Error("no replayable requests")
	}
}

func TestLogWorkerFansOut(t *testing.T) {
	db := openTestDB(t)
	var mu sync.Mutex
	seen := map[string]int{}
	hook := func(name string) func(RequestLog) {
		return func(RequestLog) { mu.Lock(); seen[name]++; mu.Unlock() }
	}
	db.SetBroadcastFn(hook("broadcast"))
	db.SetWebhookFn(hook("webhook"))
	db.SetAutobanFn(hook("autoban"))
	db.SetThreatScoreFn(hook("threatscore"))
	db.SetAccessLogFn(hook("accesslog"))
	db.SetWarehouseFn(hook("warehouse"))

	if db.QueueDepth() != 0 {
		t.Fatal("queue not empty at start")
	}
	db.QueueRequest(RequestLog{AppName: "a", RealIP: "1.1.1.1", Timestamp: time.Now(), Status: 200})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n == 6 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 6 {
		t.Fatalf("hooks called = %v", seen)
	}
	mustNoErr(t, db.Ping(context.Background()))
}

func TestReputationListings(t *testing.T) {
	db := openTestDB(t)
	mustNoErr(t, db.UpsertIPThreatScore(IPThreatScore{IP: "1.1.1.1", Total: 50, UpdatedAt: time.Now()}))
	for _, blocked := range []bool{true, false} {
		_, _, err := db.BumpJA4Reputation("t13d_abc", blocked)
		mustNoErr(t, err)
	}
	if s, _ := db.ListIPThreatScores(); len(s) != 1 || s[0].Total != 50 {
		t.Errorf("threat scores = %+v", s)
	}
	if r, _ := db.ListJA4Reputation(); len(r) != 1 || r[0].Hits != 2 || r[0].BlockedHits != 1 {
		t.Errorf("ja4 = %+v", r)
	}
}

func TestBackupTo(t *testing.T) {
	db := openTestDB(t)
	out := filepath.Join(t.TempDir(), "backup.db")
	err := db.BackupTo(out)
	if db.dialect.name != "sqlite" {
		if err == nil {
			t.Error("BackupTo should fail on external backends")
		}
		return
	}
	mustNoErr(t, err)
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		t.Fatalf("backup file: %v", err)
	}
}
