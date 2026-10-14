package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

func TestAdminRequiresSession(t *testing.T) {
	env := newAdminEnv(t)
	for _, path := range []string{"/admin", "/admin/settings", "/admin/logs"} {
		rec := env.doWith("GET", path, nil, "")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/login" {
			t.Errorf("%s without session: %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
		if rec := env.doWith("GET", path, nil, "bogus-token"); rec.Code != http.StatusFound {
			t.Errorf("%s with unknown session: %d", path, rec.Code)
		}
	}

	// A session revoked by a newer login says why.
	old := env.session
	if _, err := env.db.CreateSession("10.0.0.9", "other", ""); err != nil {
		t.Fatal(err)
	}
	rec := env.doWith("GET", "/admin", nil, old)
	if loc := rec.Header().Get("Location"); loc != "/admin/login?reason=revoked" {
		t.Errorf("revoked session redirect = %q", loc)
	}
	rec = env.doWith("GET", "/admin/login?reason=revoked", nil, "")
	if !strings.Contains(rec.Body.String(), "another device") {
		t.Error("login page should explain the revocation")
	}
}

func TestAdminMutationsRequireCSRF(t *testing.T) {
	env := newAdminEnv(t)
	req := httptest.NewRequest("POST", "/admin/ip-rules", strings.NewReader("ip=1.2.3.4&rule_type=block"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d, want 403", rec.Code)
	}
}

func TestLoginPageAndLogout(t *testing.T) {
	env := newAdminEnv(t)

	if rec := env.doWith("GET", "/admin/login", nil, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<form") {
		t.Fatalf("login page: %d", rec.Code)
	}
	// Already logged in: straight to the dashboard.
	if rec := env.do("GET", "/admin/login", nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("logged-in login page: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	rec := env.doWith("POST", "/admin/login", form("email", testAdminEmail, "password", testAdminPassword), "")
	if rec.Code != http.StatusFound || cookieByName(rec, sessionCookie) == nil || cookieByName(rec, deviceCookie) == nil {
		t.Fatalf("password login: %d", rec.Code)
	}
	newSession := cookieByName(rec, sessionCookie).Value

	rec = env.doWith("POST", "/admin/logout", nil, newSession)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/login" {
		t.Fatalf("logout: %d", rec.Code)
	}
	if sess, _ := env.db.GetSession(newSession); sess != nil {
		t.Error("logout should delete the session row")
	}
}

func TestAdminPagesRender(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	_ = env.db.AddIPRule("", "1.2.3.4", "block")
	_ = env.db.AddIPRuleWithNote("", "5.6.7.8", "block", "Auto-banned — test")
	_ = env.db.AddIPRule("shop", "10.0.0.0/8", "allow")
	_ = env.db.AddGeoRule("", "CN", "block")
	_ = env.db.AddGeoRule("shop", "US", "allow")
	_ = env.db.DisableWAFRule(942100, "noisy")
	_ = env.db.DisableWAFRuleForService(svc.Name, 920420, "uploads")
	_ = env.db.AddThreatIntelSource("Feed", "https://example.com/list.txt", 24)
	now := time.Now()
	for i, r := range []storage.RequestLog{
		{AppName: "shop", RealIP: "1.2.3.4", Country: "CN", Method: "GET", Path: "/x", Status: 403, Blocked: true, RuleID: 942100, Action: "deny", UserAgent: "sqlmap/1.7"},
		{AppName: "shop", RealIP: "8.8.8.8", Country: "US", Method: "GET", Path: "/", Status: 200, UserAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"},
		{AppName: "shop", RealIP: "9.9.9.9", Country: "DE", Method: "POST", Path: "/login", Status: 429, Blocked: true, Action: "rate_limited"},
		{AppName: "VPS", RealIP: "7.7.7.7", Country: "BR", Method: "GET", Path: "/missing", Status: 404, CacheStatus: "MISS"},
	} {
		r.Timestamp = now.Add(-time.Duration(i) * time.Minute)
		env.seedLog(r)
	}

	pages := map[string]string{
		"/admin":                   "Dashboard",
		"/admin/logs":              "Live Logs",
		"/admin/logs?mode=history": "Live Logs",
		"/admin/logs?app=shop&status=4xx&from=2020-01-01T00:00&to=2099-01-01T00:00&page=0": "Live Logs",
		"/admin/ip-rules":         "IP Rules",
		"/admin/ip-rules?page=99": "IP Rules",
		"/admin/geo-rules":        "Geo Rules",
		"/admin/services":         "Services",
		"/admin/certificates":     "Certificates",
		"/admin/waf-rules":        "WAF Rules",
		"/admin/ai-usage":         "AI Usage",
		"/admin/threat-intel":     "Threat Intel",
		"/admin/settings":         "Settings",
	}
	for path, heading := range pages {
		rec := env.do("GET", path, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), heading) {
			t.Errorf("GET %s = %d (heading %q present: %v)", path, rec.Code, heading, strings.Contains(rec.Body.String(), heading))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s missing no-store", path)
		}
	}

	if rec := env.do("GET", "/admin/ip-rules/rows?page=1", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "1.2.3.4") {
		t.Errorf("ip rule rows: %d", rec.Code)
	}
	if rec := env.do("GET", "/admin/services/rows", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shop") {
		t.Errorf("service rows: %d", rec.Code)
	}
	if rec := env.do("GET", "/admin/services/cache-stats", nil); rec.Code != http.StatusOK {
		t.Errorf("cache stats: %d", rec.Code)
	}
	// With Varnish enabled the card also reads varnishstat (absent here,
	// so it renders the error) and the per-service request-log ratios.
	_ = env.db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: storage.DefaultVarnishAddr})
	if rec := env.do("GET", "/admin/services/cache-stats", nil); rec.Code != http.StatusOK {
		t.Errorf("cache stats (enabled): %d", rec.Code)
	}
}

func TestDashboardAPIs(t *testing.T) {
	env := newAdminEnv(t)
	env.seedLog(storage.RequestLog{AppName: "a", RealIP: "1.1.1.1", Country: "CN", Status: 403, Blocked: true, Action: "deny", Method: "GET", Path: "/"})
	env.seedLog(storage.RequestLog{AppName: "a", RealIP: "2.2.2.2", Country: "US", Status: 200, Method: "GET", Path: "/"})

	var traffic struct {
		Labels  []string `json:"labels"`
		Allowed []int    `json:"allowed"`
		Blocked []int    `json:"blocked"`
	}
	rec := env.do("GET", "/admin/api/traffic", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &traffic); err != nil || len(traffic.Labels) != 24 {
		t.Fatalf("traffic: %v %s", err, rec.Body)
	}
	if traffic.Allowed[23]+traffic.Blocked[23] != 2 || traffic.Blocked[23] != 1 {
		t.Errorf("current hour = allowed %d blocked %d", traffic.Allowed[23], traffic.Blocked[23])
	}

	var threats struct {
		Labels []string `json:"labels"`
		Counts []int    `json:"counts"`
	}
	rec = env.do("GET", "/admin/api/threats", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &threats); err != nil || len(threats.Labels) != 1 || threats.Labels[0] != "CN" {
		t.Fatalf("threats: %v %s", err, rec.Body)
	}

	if rec := env.do("GET", "/admin/api/notifications", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "1.1.1.1") {
		t.Errorf("notifications panel: %d", rec.Code)
	}
	if n := env.h.unreadAlertCount(); n != 1 {
		t.Errorf("unread before seen = %d", n)
	}
	if rec := env.do("POST", "/admin/api/notifications/seen", nil); rec.Code != http.StatusNoContent {
		t.Errorf("mark seen: %d", rec.Code)
	}
	if n := env.h.unreadAlertCount(); n != 0 {
		t.Errorf("unread after seen = %d", n)
	}

	rec = env.do("GET", "/admin/logs/stats", nil)
	var seed struct {
		Events []statEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &seed); err != nil || len(seed.Events) != 2 {
		t.Errorf("stats seed: %v %s", err, rec.Body)
	}

	rec = env.do("GET", "/admin/logs/export?app=a&from=2020-01-01T00:00&to=2099-01-01T00:00", nil)
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "\n") != 2 ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), ".ndjson") {
		t.Errorf("export: %d %q", rec.Code, rec.Body)
	}

	if rec := env.do("GET", "/admin/metrics", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "palisade_") {
		t.Errorf("metrics: %d", rec.Code)
	}
}

func TestLogDetailFeedbackAndException(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	blocked := env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "1.2.3.4", Method: "GET", Path: "/q", Status: 403, Blocked: true, RuleID: 942100, Action: "deny", HeadersJSON: `{"User-Agent":"x"}`})
	clean := env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "1.2.3.5", Method: "GET", Path: "/", Status: 200})
	orphan := env.seedLog(storage.RequestLog{AppName: "gone", RealIP: "1.2.3.6", Status: 403, Blocked: true, RuleID: 1})
	badHeaders := env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "1.2.3.7", HeadersJSON: "{not json"})
	_ = env.db.UpsertIPThreatScore(storage.IPThreatScore{IP: "1.2.3.4", Total: 42, BotScore: 10, UpdatedAt: time.Now()})

	id := func(n int64) string { return strconv.FormatInt(n, 10) }

	rec := env.do("GET", "/admin/logs/"+id(blocked), nil)
	var d map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || d["path"] != "/q" || d["has_threat_score"] != true {
		t.Fatalf("detail: %v %s", err, rec.Body)
	}
	if h, _ := d["headers"].(map[string]any); h["User-Agent"] != "x" {
		t.Errorf("headers = %v", d["headers"])
	}
	if rec := env.do("GET", "/admin/logs/"+id(badHeaders), nil); rec.Code != http.StatusOK {
		t.Errorf("detail with corrupt headers: %d", rec.Code)
	}
	for path, want := range map[string]int{"/admin/logs/abc": 400, "/admin/logs/0": 400, "/admin/logs/99999": 404} {
		if rec := env.do("GET", path, nil); rec.Code != want {
			t.Errorf("GET %s = %d want %d", path, rec.Code, want)
		}
	}

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/admin/logs/feedback/" + id(blocked), 200},
		{"/admin/logs/feedback/" + id(clean), 400},
		{"/admin/logs/feedback/x", 400},
		{"/admin/logs/feedback/99999", 404},
		{"/admin/logs/exception/" + id(blocked), 200},
		{"/admin/logs/exception/" + id(clean), 400},
		{"/admin/logs/exception/" + id(orphan), 400},
		{"/admin/logs/exception/x", 400},
		{"/admin/logs/exception/99999", 404},
	} {
		if rec := env.do("POST", tc.path, form("false_positive", "1")); rec.Code != tc.want {
			t.Errorf("POST %s = %d want %d: %s", tc.path, rec.Code, tc.want, rec.Body)
		}
	}
	excs, _ := env.db.ListWAFServiceExceptions()
	if len(excs) != 1 || excs[0].RuleID != 942100 || excs[0].ServiceName != "shop" {
		t.Errorf("exceptions = %+v", excs)
	}
	if env.count("waf") != 1 {
		t.Errorf("waf reloads = %d", env.count("waf"))
	}
}

// readSSE drives an SSE handler: it waits until the handler has
// subscribed, broadcasts entries, then cancels and returns the body.
func readSSE(t *testing.T, env *adminEnv, path string, entries ...storage.RequestLog) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", path, nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { env.e.ServeHTTP(rec, req); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		env.h.broadcaster.mu.RLock()
		n := len(env.h.broadcaster.subs)
		env.h.broadcaster.mu.RUnlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, e := range entries {
		env.h.broadcaster.Broadcast(e)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	return rec.Body.String()
}

func TestSSEStreams(t *testing.T) {
	env := newAdminEnv(t)
	blocked := storage.RequestLog{ID: 7, AppName: "a", RealIP: "1.2.3.4", Method: "GET", Path: "/evil", Status: 403, Blocked: true, Action: "deny", Timestamp: time.Now()}
	clean := storage.RequestLog{ID: 8, AppName: "a", RealIP: "1.2.3.5", Method: "GET", Path: "/ok", Status: 200, Timestamp: time.Now()}

	body := readSSE(t, env, "/admin/logs/stream", clean, blocked)
	if !strings.Contains(body, "data: ") || !strings.Contains(body, "event: stat") || !strings.Contains(body, "/evil") {
		t.Errorf("logs stream body: %q", body)
	}

	body = readSSE(t, env, "/admin/api/notifications/stream", clean, blocked)
	sc := bufio.NewScanner(strings.NewReader(body))
	var events []string
	for sc.Scan() {
		if after, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
			events = append(events, after)
		}
	}
	if strings.Join(events, ",") != "count,toast" {
		t.Errorf("notification events = %v (only the blocked entry should notify)", events)
	}
}

func TestBroadcasterRingBuffer(t *testing.T) {
	b := NewLogBroadcaster()
	ch := b.Subscribe()
	for i := range recentBufSize + 5 {
		b.Broadcast(storage.RequestLog{ID: i})
	}
	if len(b.recent) != recentBufSize || b.recent[0].ID != 5 {
		t.Errorf("ring buffer len=%d first=%d", len(b.recent), b.recent[0].ID)
	}
	if len(ch) != cap(ch) {
		t.Errorf("slow subscriber should have a full buffer, not block: %d/%d", len(ch), cap(ch))
	}
	b.Unsubscribe(ch)
	if _, ok := <-drain(ch); ok {
		t.Error("channel should be closed after Unsubscribe")
	}
}

func drain(ch chan storage.RequestLog) chan storage.RequestLog {
	for range len(ch) {
		<-ch
	}
	return ch
}
