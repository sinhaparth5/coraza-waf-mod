package ui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

func itoa[T int | int64](n T) string { return strconv.FormatInt(int64(n), 10) }

// wantCode fails unless rec has the given status.
func wantCode(t *testing.T, label string, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: status %d want %d: %s", label, got, want, body)
	}
}

func TestIPRuleHandlers(t *testing.T) {
	env := newAdminEnv(t)
	for _, tc := range []struct {
		ip, typ string
		want    int
	}{
		{"", "block", 400},
		{"1.2.3.4", "maybe", 400},
		{"not-an-ip", "block", 400},
		{"10.0.1.5/24", "block", 200},
		{"::ffff:1.2.3.4", "allow", 200},
		{"2001:db8::1", "block", 200},
	} {
		rec := env.do("POST", "/admin/ip-rules", form("ip", tc.ip, "rule_type", tc.typ))
		wantCode(t, "add "+tc.ip, rec.Code, tc.want, rec.Body.String())
	}
	rules, _ := env.db.ListIPRules()
	got := map[string]string{}
	for _, r := range rules {
		got[r.IP] = r.RuleType
	}
	if got["10.0.1.0/24"] != "block" || got["1.2.3.4"] != "allow" || got["2001:db8::1"] != "block" {
		t.Fatalf("stored rules not canonicalised: %v", got)
	}
	if blocked, _ := env.h.ipbl.Check("10.0.1.9", ""); !blocked {
		t.Error("blocklist not reloaded after add")
	}

	rec := env.do("DELETE", "/admin/ip-rules/"+itoa(rules[0].ID)+"?page=3", nil)
	wantCode(t, "delete", rec.Code, 200, rec.Body.String())
	wantCode(t, "delete bad id", env.do("DELETE", "/admin/ip-rules/x", nil).Code, 400, "")
	if rules2, _ := env.db.ListIPRules(); len(rules2) != len(rules)-1 {
		t.Error("rule not deleted")
	}
}

func TestAutobanAndAdaptiveSettings(t *testing.T) {
	env := newAdminEnv(t)
	rec := env.do("POST", "/admin/ip-rules/autoban", form("autoban_enabled", "1", "autoban_threshold", "25", "autoban_window", "60"))
	wantCode(t, "autoban", rec.Code, 200, rec.Body.String())
	ab, _ := env.db.GetAutobanConfig()
	if !ab.Enabled || ab.Threshold != 25 || ab.WindowMinutes != 60 || env.count("autoban") != 1 {
		t.Errorf("autoban = %+v reloads=%d", ab, env.count("autoban"))
	}
	// Out-of-range values fall back to defaults instead of being stored.
	env.do("POST", "/admin/ip-rules/autoban", form("autoban_threshold", "0", "autoban_window", "99999"))
	ab, _ = env.db.GetAutobanConfig()
	def := storage.DefaultAutobanConfig()
	if ab.Enabled || ab.Threshold != def.Threshold || ab.WindowMinutes != def.WindowMinutes {
		t.Errorf("autoban out-of-range = %+v", ab)
	}

	rec = env.do("POST", "/admin/ip-rules/adaptive", form(
		"adaptive_enabled", "1", "adaptive_high_threshold", "70", "adaptive_low_threshold", "5",
		"adaptive_high_rate_scale", "0.25", "adaptive_low_rate_scale", "2", "adaptive_force_challenge_threshold", "90"))
	wantCode(t, "adaptive", rec.Code, 200, rec.Body.String())
	ad, _ := env.db.GetAdaptiveEnforcementConfig()
	if !ad.Enabled || ad.HighRiskThreshold != 70 || ad.LowRiskThreshold != 5 || ad.HighRiskRateScale != 0.25 ||
		ad.LowRiskRateScale != 2 || ad.ForceChallengeThreshold != 90 || env.count("adaptive") != 1 {
		t.Errorf("adaptive = %+v", ad)
	}
}

func TestGeoRuleHandlers(t *testing.T) {
	env := newAdminEnv(t)
	wantCode(t, "bad code", env.do("POST", "/admin/geo-rules", form("country_code", "USA", "rule_type", "block")).Code, 400, "")
	wantCode(t, "bad type", env.do("POST", "/admin/geo-rules", form("country_code", "US", "rule_type", "x")).Code, 400, "")
	rec := env.do("POST", "/admin/geo-rules", form("country_code", " cn ", "rule_type", "block"))
	wantCode(t, "add", rec.Code, 200, rec.Body.String())
	rules, _ := env.db.ListGeoRules()
	if len(rules) != 1 || rules[0].CountryCode != "CN" {
		t.Fatalf("geo rules = %+v", rules)
	}
	wantCode(t, "delete bad", env.do("DELETE", "/admin/geo-rules/x", nil).Code, 400, "")
	wantCode(t, "delete", env.do("DELETE", "/admin/geo-rules/"+itoa(rules[0].ID), nil).Code, 200, "")
	if rules, _ := env.db.ListGeoRules(); len(rules) != 0 {
		t.Error("geo rule not deleted")
	}
}

func TestWAFRuleHandlers(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	wantCode(t, "bad id", env.do("POST", "/admin/waf-rules/disable", form("rule_id", "abc")).Code, 400, "")
	wantCode(t, "zero id", env.do("POST", "/admin/waf-rules/disable", form("rule_id", "0")).Code, 400, "")
	wantCode(t, "global", env.do("POST", "/admin/waf-rules/disable", form("rule_id", "942100", "reason", "fp")).Code, 200, "")
	wantCode(t, "service", env.do("POST", "/admin/waf-rules/disable", form("rule_id", "920420", "service", "shop")).Code, 200, "")
	if env.count("waf") != 2 {
		t.Errorf("waf reloads = %d", env.count("waf"))
	}
	dis, _ := env.db.ListDisabledWAFRules()
	exc, _ := env.db.ListWAFServiceExceptions()
	if len(dis) != 1 || len(exc) != 1 {
		t.Fatalf("disabled=%v exceptions=%v", dis, exc)
	}
	wantCode(t, "enable", env.do("DELETE", "/admin/waf-rules/"+itoa(dis[0].ID), nil).Code, 200, "")
	wantCode(t, "enable bad", env.do("DELETE", "/admin/waf-rules/x", nil).Code, 400, "")
	wantCode(t, "enable svc", env.do("DELETE", "/admin/waf-rules/service/"+itoa(exc[0].ID), nil).Code, 200, "")
	wantCode(t, "enable svc bad", env.do("DELETE", "/admin/waf-rules/service/x", nil).Code, 400, "")
	dis, _ = env.db.ListDisabledWAFRules()
	exc, _ = env.db.ListWAFServiceExceptions()
	if len(dis)+len(exc) != 0 {
		t.Error("rules not re-enabled")
	}

	wantCode(t, "feedback cfg", env.do("POST", "/admin/waf-rules/feedback-config", form("feedback_threshold", "7", "feedback_window", "30")).Code, 200, "")
	if fc, _ := env.db.GetWAFRuleFeedbackConfig(); fc.Threshold != 7 || fc.WindowDays != 30 {
		t.Errorf("feedback cfg = %+v", fc)
	}
}

func TestWAFDryRunHandler(t *testing.T) {
	env := newAdminEnv(t)
	env.seedLog(storage.RequestLog{AppName: "a", Method: "GET", Host: "a.test", Path: "/hello", Query: "x=1", Status: 200})

	for _, tc := range []struct{ rules, want string }{
		{"", "Paste at least one rule"},
		{"this is not a directive", "don&#39;t compile"},
		{`SecRule ARGS:x "@streq 1" "id:9000001,phase:2,deny,status:403"`, "hello"},
	} {
		rec := env.do("POST", "/admin/waf-rules/dry-run", form("rules", tc.rules, "limit", "-1"))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("dry run %q: %d %s", tc.rules, rec.Code, rec.Body)
		}
	}

	env.h.cfg.WAF.Enabled = false
	rec := env.do("POST", "/admin/waf-rules/dry-run", form("rules", "x"))
	if !strings.Contains(rec.Body.String(), "WAF is disabled") {
		t.Errorf("disabled WAF: %s", rec.Body)
	}
}

func TestThreatIntelHandlers(t *testing.T) {
	env := newAdminEnv(t)
	wantCode(t, "missing", env.do("POST", "/admin/threat-intel", form("label", "x")).Code, 400, "")
	wantCode(t, "bad url", env.do("POST", "/admin/threat-intel", form("label", "x", "url", "file:///etc/passwd")).Code, 400, "")
	wantCode(t, "add", env.do("POST", "/admin/threat-intel", form("label", "Feed", "url", "https://example.com/l.txt", "interval_hours", "0")).Code, 200, "")
	wantCode(t, "dup", env.do("POST", "/admin/threat-intel", form("label", "Feed", "url", "https://example.com/l.txt")).Code, 409, "")
	srcs, _ := env.db.ListThreatIntelSources()
	if len(srcs) != 1 || srcs[0].IntervalHours != 24 {
		t.Fatalf("sources = %+v", srcs)
	}
	id := itoa(srcs[0].ID)
	wantCode(t, "toggle", env.do("POST", "/admin/threat-intel/"+id+"/toggle", form("enabled", "0")).Code, 200, "")
	if srcs, _ := env.db.ListThreatIntelSources(); srcs[0].Enabled {
		t.Error("toggle did not disable")
	}
	wantCode(t, "sync", env.do("POST", "/admin/threat-intel/"+id+"/sync", nil).Code, 200, "")
	if env.count("intel") != 1 {
		t.Error("sync callback not called")
	}
	for _, p := range []string{"/admin/threat-intel/x/toggle", "/admin/threat-intel/x/sync"} {
		wantCode(t, p, env.do("POST", p, nil).Code, 400, "")
	}
	wantCode(t, "delete bad", env.do("DELETE", "/admin/threat-intel/x", nil).Code, 400, "")
	wantCode(t, "delete", env.do("DELETE", "/admin/threat-intel/"+id, nil).Code, 200, "")
	if srcs, _ := env.db.ListThreatIntelSources(); len(srcs) != 0 {
		t.Error("source not deleted")
	}
}

func TestAddAndDeleteService(t *testing.T) {
	env := newAdminEnv(t)
	for _, tc := range []struct {
		name string
		f    []string
		want string
	}{
		{"missing fields", []string{"name", "x"}, "fill in all required"},
		{"bad match type", []string{"name", "x", "match_type", "path", "match_value", "/", "backend", env.backend.URL}, "fill in all required"},
		{"metadata backend", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", "http://169.254.169.254"}, ""},
		{"dead backend", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", "http://127.0.0.1:1"}, "Fix the backend"},
		{"bad rps", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", env.backend.URL, "rps", "fast"}, "must be a number"},
		{"bad burst", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", env.backend.URL, "burst", "1.5"}, "whole number"},
	} {
		rec := env.do("POST", "/admin/services", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#wizard-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: retarget=%q body=%s", tc.name, rec.Header().Get("HX-Retarget"), rec.Body)
		}
	}

	rec := env.do("POST", "/admin/services", form("name", "shop", "match_type", "host", "match_value", "https://shop.example.com/", "backend", env.backend.URL, "rps", "-1", "burst", "-3"))
	wantCode(t, "add host", rec.Code, 200, rec.Body.String())
	rec = env.do("POST", "/admin/services", form("name", "api", "match_type", "prefix", "match_value", "/api", "backend", env.backend.URL, "rps", "5", "burst", "10"))
	wantCode(t, "add prefix", rec.Code, 200, rec.Body.String())
	svcs, _ := env.db.ListServices()
	if len(svcs) != 2 || svcs[0].Host != "shop.example.com" || svcs[0].RateLimitRPS != 0 || svcs[1].Prefix != "/api" || svcs[1].RateLimitBurst != 10 {
		t.Fatalf("services = %+v", svcs)
	}
	if !env.h.registry.IsServiceHost("shop.example.com") {
		t.Error("registry not reloaded")
	}

	wantCode(t, "delete bad", env.do("DELETE", "/admin/services/x", nil).Code, 400, "")
	wantCode(t, "delete", env.do("DELETE", "/admin/services/"+itoa(svcs[0].ID), nil).Code, 200, "")
	if env.h.registry.IsServiceHost("shop.example.com") {
		t.Error("deleted service still routed")
	}
}

func TestServiceSettingHandlers(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	id := itoa(svc.ID)

	for _, tc := range []struct {
		path string
		f    []string
		want int
	}{
		{"/admin/services/bot/" + id, []string{"bot_mode", "always"}, 200},
		{"/admin/services/bot/0", nil, 400},
		{"/admin/services/uploads/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/uploads/x", nil, 400},
		{"/admin/services/http3/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/http3/x", nil, 400},
		{"/admin/services/compress/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/compress/x", nil, 400},
		{"/admin/services/backends/" + id, []string{"backends", "http://127.0.0.1:9001\nhttp://127.0.0.1:9002", "lb_policy", "least_conn", "health_path", "/healthz", "health_interval", "30"}, 200},
		{"/admin/services/schema/" + id, []string{"mode", "enforce", "schema", `{"type":"object"}`}, 200},
		{"/admin/services/schema/" + id, []string{"mode", "log", "schema", `{"type":`}, 400},
		{"/admin/services/schema/x", nil, 400},
		{"/admin/services/cache/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/cache/x", nil, 400},
		{"/admin/services/cache-session/" + id, []string{"session_enabled", "1"}, 400},
		{"/admin/services/cache-session/" + id, []string{"session_enabled", "1", "session_cookie_name", "sid"}, 200},
		{"/admin/services/cache-session/x", nil, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_floor", "60", "ttl_ceiling", "600", "grace", "10", "keep", ""}, 200},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_floor", "-1"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_ceiling", "x"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"grace", "x"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"keep", "x"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_floor", "100", "ttl_ceiling", "50"}, 400},
		{"/admin/services/cache-tuning/x", nil, 400},
	} {
		rec := env.do("POST", tc.path, form(tc.f...))
		wantCode(t, tc.path+" "+strings.Join(tc.f, "="), rec.Code, tc.want, rec.Body.String())
	}

	// Backend list errors land in the tab's error box, escaped.
	rec := env.do("POST", "/admin/services/backends/"+id, form("backends", "http://127.0.0.1:1/<b>\nhttp://127.0.0.2:1/"))
	if rec.Header().Get("HX-Retarget") != "#svc-backends-error" || strings.Contains(rec.Body.String(), "<b>") {
		t.Errorf("backends error = %q (retarget %q)", rec.Body.String(), rec.Header().Get("HX-Retarget"))
	}

	// Hosts tab: a name another service owns is refused in the tab's error box.
	env.seedService("blog", "blog.example.com")
	rec = env.do("POST", "/admin/services/hosts/"+id, form("aliases", "blog.example.com"))
	if rec.Header().Get("HX-Retarget") != "#svc-hosts-error" || !strings.Contains(rec.Body.String(), "blog") {
		t.Errorf("hosts conflict = %q (retarget %q)", rec.Body.String(), rec.Header().Get("HX-Retarget"))
	}
	rec = env.do("POST", "/admin/services/hosts/"+id, form("aliases", "WWW.shop.example.com\n", "canonical", "shop.example.com"))
	if rec.Header().Get("HX-Trigger") != "hosts-saved" {
		t.Errorf("hosts save = %d %q", rec.Code, rec.Body.String())
	}
	if !env.h.registry.IsServiceHost("www.shop.example.com") {
		t.Error("alias not routed after save")
	}

	got, _ := env.db.GetService(svc.ID)
	if len(got.HostAliases) != 1 || got.HostAliases[0] != "www.shop.example.com" || got.CanonicalHost != "shop.example.com" {
		t.Errorf("hosts = %v %q", got.HostAliases, got.CanonicalHost)
	}
	if got.BotMode != "always" || !got.AllowLargeJSUploads || !got.HTTP3Enabled || !got.CompressEnabled || len(got.ExtraBackends) != 1 || got.LBPolicy != "least_conn" || got.HealthPath != "/healthz" || got.SchemaMode != "enforce" || !got.CacheEnabled ||
		!got.CacheBySession || got.SessionCookieName != "sid" || got.CacheTTLFloor != 60 || got.CacheTTLCeiling != 600 || got.CacheGrace != 10 {
		t.Errorf("service = %+v", got)
	}
	if env.count("waf") != 2 { // uploads + schema
		t.Errorf("waf reloads = %d", env.count("waf"))
	}

	// Rate limit tab.
	for _, tc := range []struct {
		f      []string
		code   int
		errBox bool
	}{
		{[]string{"service_id", "x"}, 400, false},
		{[]string{"service_id", id, "rps", "x"}, 200, true},
		{[]string{"service_id", id, "burst", "x"}, 200, true},
		{[]string{"service_id", id, "rps", "-2", "burst", "-1"}, 200, false},
		{[]string{"service_id", id, "rps", "3", "burst", "6"}, 200, false},
	} {
		rec := env.do("POST", "/admin/services/ratelimit", form(tc.f...))
		wantCode(t, "ratelimit", rec.Code, tc.code, rec.Body.String())
		if (rec.Header().Get("HX-Retarget") == "#rl-error") != tc.errBox {
			t.Errorf("ratelimit %v: retarget=%q", tc.f, rec.Header().Get("HX-Retarget"))
		}
	}
	if got, _ := env.db.GetService(svc.ID); got.RateLimitRPS != 3 || got.RateLimitBurst != 6 {
		t.Errorf("rate limit = %v/%v", got.RateLimitRPS, got.RateLimitBurst)
	}

	// Purge: invalid id / unknown service / Varnish unreachable all report inline.
	for path, want := range map[string]string{
		"/admin/services/cache-purge/x":     "invalid service id",
		"/admin/services/cache-purge/99999": "service not found",
		"/admin/services/cache-purge/" + id: "text-red-500",
	} {
		rec := env.do("POST", path, form("path", "/blog/"))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("purge %s: %s", path, rec.Body)
		}
	}
}

// testCertPEM returns a self-signed cert+key for the given DNS names.
func testCertPEM(t *testing.T, names ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestCertificateAndTLSHandlers(t *testing.T) {
	t.Chdir(t.TempDir()) // cert files are written relative to the working directory
	env := newAdminEnv(t)
	host := env.seedService("shop", "shop.example.com")
	prefix := storage.Service{}
	_ = env.db.AddService("api", "", "/api", env.backend.URL, 0, 0)
	svcs, _ := env.db.ListServices()
	for _, s := range svcs {
		if s.Name == "api" {
			prefix = s
		}
	}
	certPEM, keyPEM := testCertPEM(t, "shop.example.com")
	otherCert, otherKey := testCertPEM(t, "other.example.com")

	// Pool certificates.
	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"cert_pem", certPEM, "key_pem", keyPEM}, "name is required"},
		{[]string{"name", "x"}, "paste both"},
		{[]string{"name", "x", "cert_pem", "junk", "key_pem", "junk"}, "invalid certificate"},
		{[]string{"name", "x", "cert_pem", certPEM, "key_pem", otherKey}, "invalid cert/key pair"},
	} {
		rec := env.do("POST", "/admin/certificates", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#cert-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("add cert %v: %s", tc.want, rec.Body)
		}
	}
	wantCode(t, "add cert", env.do("POST", "/admin/certificates", form("name", "cert.pem", "cert_pem", certPEM, "key_pem", keyPEM)).Code, 200, "")
	wantCode(t, "add other", env.do("POST", "/admin/certificates", form("name", "cert.pem", "cert_pem", otherCert, "key_pem", otherKey)).Code, 200, "")
	certs, _ := env.db.ListCertificates()
	if len(certs) != 2 || certs[1].Name != "other.example.com" {
		t.Fatalf("certs = %+v (duplicate name should fall back to the domain)", certs)
	}
	if _, err := os.Stat(certs[0].KeyPath); err != nil {
		t.Errorf("pool key not written: %v", err)
	}

	// Assign from the pool.
	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"service_id", "x"}, "invalid service"},
		{[]string{"service_id", itoa(host.ID), "cert_id", "0"}, "select a certificate"},
		{[]string{"service_id", "99999", "cert_id", "1"}, "service not found"},
		{[]string{"service_id", itoa(prefix.ID), "cert_id", "1"}, "host-matched"},
		{[]string{"service_id", itoa(host.ID), "cert_id", "99999"}, "certificate not found"},
		{[]string{"service_id", itoa(host.ID), "cert_id", itoa(certs[1].ID)}, "shop.example.com"},
	} {
		rec := env.do("POST", "/admin/services/tls/pool", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#tls-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("assign %q: %s", tc.want, rec.Body)
		}
	}
	rec := env.do("POST", "/admin/services/tls/pool", form("service_id", itoa(host.ID), "cert_id", itoa(certs[0].ID)))
	if rec.Header().Get("HX-Trigger") != "tls-saved" {
		t.Errorf("assign ok: %s", rec.Body)
	}
	if got, _ := env.db.GetService(host.ID); got.CertID != certs[0].ID {
		t.Errorf("cert not assigned: %+v", got)
	}

	// Custom upload.
	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"service_id", "x"}, "invalid service"},
		{[]string{"service_id", "99999"}, "service not found"},
		{[]string{"service_id", itoa(prefix.ID)}, "host-matched"},
		{[]string{"service_id", itoa(host.ID)}, "paste both"},
		{[]string{"service_id", itoa(host.ID), "cert_pem", otherCert, "key_pem", otherKey}, "shop.example.com"},
		{[]string{"service_id", itoa(host.ID), "cert_pem", certPEM, "key_pem", otherKey}, "invalid"},
	} {
		rec := env.do("POST", "/admin/services/tls/upload", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#tls-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("upload %q: %s", tc.want, rec.Body)
		}
	}
	rec = env.do("POST", "/admin/services/tls/upload", form("service_id", itoa(host.ID), "cert_pem", certPEM, "key_pem", keyPEM))
	if rec.Header().Get("HX-Trigger") != "tls-saved" {
		t.Errorf("upload ok: %s", rec.Body)
	}
	if got, _ := env.db.GetService(host.ID); got.TLSMode != "custom" {
		t.Errorf("tls mode = %q", got.TLSMode)
	}
	if _, err := os.Stat(filepath.Join("certs", "services", "shop")); err != nil {
		t.Errorf("custom cert dir: %v", err)
	}

	// Auto TLS: no ACME email yet asks the UI to collect one.
	for _, tc := range []struct{ id, want string }{{"x", "invalid service"}, {"99999", "service not found"}, {itoa(prefix.ID), "host-matched"}} {
		if rec := env.do("POST", "/admin/services/tls/auto", form("service_id", tc.id)); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("auto %s: %s", tc.id, rec.Body)
		}
	}
	rec = env.do("POST", "/admin/services/tls/auto", form("service_id", itoa(host.ID)))
	if !strings.Contains(rec.Header().Get("HX-Trigger"), "need-acme-email") {
		t.Errorf("auto without email: %q", rec.Header().Get("HX-Trigger"))
	}
	if rec := env.do("POST", "/admin/settings/acme-email", form("email", "nope")); rec.Header().Get("HX-Retarget") != "#acme-email-error" {
		t.Error("invalid ACME email accepted")
	}
	rec = env.do("POST", "/admin/settings/acme-email", form("email", "ops@example.com", "service_id", itoa(host.ID)))
	// Both events: tls-saved closes the TLS modal, acme-email-saved the email one.
	if rec.Header().Get("HX-Trigger") != "tls-saved, acme-email-saved" {
		t.Errorf("acme email: %q", rec.Header().Get("HX-Trigger"))
	}
	if got, _ := env.db.GetService(host.ID); got.TLSMode != "auto" {
		t.Errorf("tls mode after acme = %q", got.TLSMode)
	}
	if rec := env.do("POST", "/admin/services/tls/auto", form("service_id", itoa(host.ID))); rec.Header().Get("HX-Trigger") != "tls-saved" {
		t.Errorf("auto with email: %q", rec.Header().Get("HX-Trigger"))
	}

	if rec := env.do("POST", "/admin/services/tls/clear", form("service_id", "x")); !strings.Contains(rec.Body.String(), "invalid service") {
		t.Error("clear bad id")
	}
	env.do("POST", "/admin/services/tls/clear", form("service_id", itoa(host.ID)))
	if got, _ := env.db.GetService(host.ID); got.TLSMode != "" && got.TLSMode != "none" {
		t.Errorf("tls mode after clear = %q", got.TLSMode)
	}

	wantCode(t, "delete cert bad", env.do("DELETE", "/admin/certificates/x", nil).Code, 400, "")
	wantCode(t, "delete cert", env.do("DELETE", "/admin/certificates/"+itoa(certs[0].ID), nil).Code, 200, "")
	if _, err := os.Stat(filepath.Dir(certs[0].CertPath)); !os.IsNotExist(err) {
		t.Error("pool cert dir not removed")
	}
}

func TestSettingsCards(t *testing.T) {
	env := newAdminEnv(t)

	// Bot protection.
	env.do("POST", "/admin/settings/bot", form("bot_enabled", "1", "bot_threshold", "0", "bot_ttl", "-5"))
	if en, th, ttl, _ := env.db.GetBotSettings(); !en || th != 8 || ttl != 3600 || env.count("bot") != 1 {
		t.Errorf("bot = %v %d %d reloads=%d", en, th, ttl, env.count("bot"))
	}

	// Varnish: non-loopback rejected, loopback saved.
	for addr, wantErr := range map[string]string{"bad": "host:port", "10.0.0.1:6081": "loopback", "": ""} {
		rec := env.do("POST", "/admin/settings/varnish", form("varnish_enabled", "1", "varnish_addr", addr))
		if wantErr != "" && !strings.Contains(rec.Body.String(), wantErr) {
			t.Errorf("varnish %q: %s", addr, rec.Body)
		}
	}
	if vc, _ := env.db.GetVarnishConfig(); !vc.Enabled || vc.Addr != storage.DefaultVarnishAddr {
		t.Errorf("varnish = %+v", vc)
	}

	// Rate limit.
	for _, tc := range []struct {
		f       []string
		wantErr string
	}{
		{[]string{"rl_enabled", "1", "rl_rps", "0", "rl_burst", "5"}, "positive numbers"},
		{[]string{"rl_enabled", "1", "rl_rps", "5", "rl_burst", "10", "rl_backend", "redis"}, "must not be empty"},
		{[]string{"rl_enabled", "1", "rl_rps", "5", "rl_burst", "10", "rl_backend", "redis", "rl_redis_addr", "127.0.0.1:1"}, "connection failed"},
		{[]string{"rl_enabled", "1", "rl_rps", "5", "rl_burst", "10", "rl_backend", "memory"}, ""},
		{[]string{"rl_backend", "memory"}, ""}, // disabled with blank numbers keeps stored ones
	} {
		rec := env.do("POST", "/admin/settings/ratelimit", form(tc.f...))
		if tc.wantErr != "" && !strings.Contains(rec.Body.String(), tc.wantErr) {
			t.Errorf("ratelimit %v: %s", tc.f, rec.Body)
		}
	}
	if en, rps, burst, _ := env.db.GetRateLimitSettings(); en || rps != 5 || burst != 10 {
		t.Errorf("rate limit = %v %v %v", en, rps, burst)
	}
	if env.count("ratelimit") != 2 {
		t.Errorf("ratelimit reloads = %d", env.count("ratelimit"))
	}
	for addr, want := range map[string]string{"": "Address is required", "127.0.0.1:1": "Connection failed"} {
		if rec := env.do("POST", "/admin/settings/ratelimit/test", form("rl_redis_addr", addr)); !strings.Contains(rec.Body.String(), want) {
			t.Errorf("redis test %q: %s", addr, rec.Body)
		}
	}
	if addr := os.Getenv("TEST_REDIS_ADDR"); addr != "" {
		if rec := env.do("POST", "/admin/settings/ratelimit/test", form("rl_redis_addr", addr)); !strings.Contains(rec.Body.String(), "Connected") {
			t.Errorf("redis test live: %s", rec.Body)
		}
		env.do("POST", "/admin/settings/ratelimit", form("rl_enabled", "1", "rl_rps", "5", "rl_burst", "10", "rl_backend", "redis", "rl_redis_addr", addr))
		if got, _, _ := env.db.GetRedisConfig(); got != addr {
			t.Errorf("redis addr = %q", got)
		}
	}

	// Webhook.
	if rec := env.do("POST", "/admin/settings/webhook", form("webhook_url", "ftp://x", "webhook_enabled", "1")); !strings.Contains(rec.Body.String(), "absolute http") {
		t.Errorf("webhook bad url: %s", rec.Body)
	}
	env.do("POST", "/admin/settings/webhook", url2(form("webhook_url", "https://hooks.example.com/x", "webhook_enabled", "1", "webhook_destination_type", "bogus"), "webhook_events", "blocked", "challenged"))
	if wh, _ := env.db.GetWebhookConfig(); !wh.Enabled || wh.Events != "blocked,challenged" || wh.DestinationType != "generic" {
		t.Errorf("webhook = %+v", wh)
	}
	if rec := env.do("POST", "/admin/settings/webhook/test", nil); !strings.Contains(rec.Body.String(), "Test alert sent") || env.count("webhook") != 1 {
		t.Errorf("webhook test: %s", rec.Body)
	}

	// Email: enabling needs recipient + token; blank token keeps the stored one.
	if rec := env.do("POST", "/admin/settings/email", form("email_enabled", "1")); !strings.Contains(rec.Body.String(), "required") {
		t.Errorf("email missing: %s", rec.Body)
	}
	env.do("POST", "/admin/settings/email", form("email_enabled", "1", "email_to", "a@b.c", "email_token", "tok"))
	env.do("POST", "/admin/settings/email", form("email_enabled", "1", "email_to", "x@y.z"))
	if ec, _ := env.db.GetEmailConfig(); !ec.Enabled || ec.To != "x@y.z" || ec.Token != "tok" {
		t.Errorf("email = %+v", ec)
	}
	if rec := env.do("POST", "/admin/settings/email/test", nil); !strings.Contains(rec.Body.String(), "Report sent") || env.count("report") != 1 {
		t.Errorf("email test: %s", rec.Body)
	}

	// TypeSafe.
	if rec := env.do("POST", "/admin/settings/typesafe", form("typesafe_enabled", "1")); !strings.Contains(rec.Body.String(), "API key is required") {
		t.Errorf("typesafe missing key: %s", rec.Body)
	}
	env.do("POST", "/admin/settings/typesafe", form("typesafe_enabled", "1", "typesafe_api_key", "k"))
	env.do("POST", "/admin/settings/typesafe", form("typesafe_enabled", "1"))
	if tc, _ := env.db.GetTypeSafeConfig(); !tc.Enabled || tc.APIKey != "k" {
		t.Errorf("typesafe = %+v", tc)
	}

	// API keys.
	if rec := env.do("POST", "/admin/settings/api-keys", form("name", " ")); !strings.Contains(rec.Body.String(), "Name is required") {
		t.Errorf("api key no name: %s", rec.Body)
	}
	rec := env.do("POST", "/admin/settings/api-keys", form("name", "ci", "read_only", "1"))
	if !strings.Contains(rec.Body.String(), "cwaf_") {
		t.Errorf("new key not shown: %s", rec.Body)
	}
	keys, _ := env.db.ListAPIKeys()
	if len(keys) != 1 || !keys[0].ReadOnly {
		t.Fatalf("keys = %+v", keys)
	}
	wantCode(t, "delete key bad", env.do("DELETE", "/admin/settings/api-keys/x", nil).Code, 400, "")
	env.do("DELETE", "/admin/settings/api-keys/"+itoa(keys[0].ID), nil)
	if keys, _ := env.db.ListAPIKeys(); len(keys) != 0 {
		t.Error("api key not deleted")
	}

	// Devices: revoke every other session.
	other, _ := env.db.CreateSession("10.0.0.2", "other", "dev2") // revokes env.session...
	env.session = other                                           // ...so continue as the new one
	mine, _ := env.db.GetSession(other)
	if !mine.Live() {
		t.Fatal("precondition: new session live")
	}
	wantCode(t, "revoke others", env.do("POST", "/admin/settings/devices/revoke-others", nil).Code, 200, "")
}

// url2 appends repeated values for a multi-value field.
func url2(v map[string][]string, key string, vals ...string) map[string][]string {
	v[key] = append(v[key], vals...)
	return v
}

func TestDBConnHandlers(t *testing.T) {
	env := newAdminEnv(t)
	if rec := env.do("POST", "/admin/settings/dbconn", form()); !strings.Contains(rec.Body.String(), "Select a database driver") {
		t.Errorf("save no driver: %s", rec.Body)
	}
	env.do("POST", "/admin/settings/dbconn", form("dbconn_driver", "postgres", "dbconn_host", "db.internal", "dbconn_password", "s3cret", "dbconn_mode", "weird"))
	cfg, _ := env.db.GetDBConnConfig()
	if cfg.Driver != "postgres" || cfg.Mode != "fields" || cfg.Password != "s3cret" {
		t.Errorf("dbconn = %+v", cfg)
	}
	if rec := env.do("GET", "/admin/settings", nil); strings.Contains(rec.Body.String(), "s3cret") {
		t.Error("stored DB password echoed into the settings page")
	}

	env.seedService("shop", "shop.example.com") // a row the second migrate collides on
	target := filepath.Join(t.TempDir(), "target.db")
	for _, tc := range []struct {
		f    []string
		want string
	}{
		{nil, "select a database driver"},
		{[]string{"dbconn_driver", "sqlite"}, "file path is required"},
		{[]string{"dbconn_driver", "mysql", "dbconn_mode", "dsn"}, "connection string is required"},
		{[]string{"dbconn_driver", "mysql"}, "host is required"},
		{[]string{"dbconn_driver", "postgres", "dbconn_host", "127.0.0.1", "dbconn_port", "1", "dbconn_username", "u", "dbconn_dbname", "d", "dbconn_sslmode", "disable"}, "Connection failed"},
		{[]string{"dbconn_driver", "sqlite", "dbconn_host", target}, "Connected successfully"},
	} {
		if rec := env.do("POST", "/admin/settings/dbconn/test", form(tc.f...)); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("test %v: %s", tc.f, rec.Body)
		}
	}

	if rec := env.do("POST", "/admin/settings/dbconn/migrate", form()); !strings.Contains(rec.Body.String(), "select a database driver") {
		t.Errorf("migrate no driver: %s", rec.Body)
	}
	if rec := env.do("POST", "/admin/settings/dbconn/migrate", form("dbconn_driver", "sqlite", "dbconn_host", target)); !strings.Contains(rec.Body.String(), "Migrated") {
		t.Errorf("migrate: %s", rec.Body)
	}
	// Running it again hits duplicate keys and reports the failure.
	if rec := env.do("POST", "/admin/settings/dbconn/migrate", form("dbconn_driver", "sqlite", "dbconn_host", target)); !strings.Contains(rec.Body.String(), "Migration failed") {
		t.Errorf("re-migrate: %s", rec.Body)
	}
}

func TestChangeCredentialsAndBackup(t *testing.T) {
	env := newAdminEnv(t)

	rec := env.do("POST", "/admin/settings/backup", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "SQLite format 3") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "palisade-") {
		t.Errorf("backup: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}

	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"current_password", "wrong"}, "Current password is incorrect"},
		{[]string{"current_password", testAdminPassword, "new_password", "abcdefgh", "confirm_password", "x"}, "do not match"},
		{[]string{"current_password", testAdminPassword, "new_password", "short", "confirm_password", "short"}, "at least 8"},
	} {
		if rec := env.do("POST", "/admin/settings/credentials", form(tc.f...)); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("credentials %q: %s", tc.want, rec.Body)
		}
	}
	rec = env.do("POST", "/admin/settings/credentials", form("current_password", testAdminPassword, "new_email", "new@example.com", "new_password", "a-new-password", "confirm_password", "a-new-password"))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/login" {
		t.Fatalf("credentials ok: %d", rec.Code)
	}
	if ok, _ := env.db.CheckAdminPassword("a-new-password"); !ok {
		t.Error("password not changed")
	}
	if email, _ := env.db.GetAdminEmail(); email != "new@example.com" {
		t.Errorf("email = %q", email)
	}
	if sess, _ := env.db.GetSession(env.session); sess != nil {
		t.Error("session should be dropped after a credential change")
	}
}

func TestPasskeyHandlers(t *testing.T) {
	env := newAdminEnv(t)

	// Plain HTTP on a non-localhost host can't do WebAuthn at all.
	req := env.do("POST", "/admin/settings/passkeys/begin", nil)
	wantCode(t, "insecure begin", req.Code, http.StatusBadRequest, req.Body.String())

	secure := func(method, path, body string) *httptestRecorder {
		r := newReq(env, method, path, body)
		r.Host = "localhost"
		return serve(env, r)
	}
	rec := secure("POST", "/admin/settings/passkeys/begin", `{"name":"YubiKey"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("begin enrollment: %d %s", rec.Code, rec.Body)
	}
	if rec := secure("POST", "/admin/settings/passkeys/finish", `{}`); rec.Code != 400 {
		t.Errorf("finish with bogus attestation = %d", rec.Code)
	}
	if rec := secure("POST", "/admin/settings/passkeys/finish", `{}`); !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("finish without a pending ceremony: %s", rec.Body)
	}

	_ = env.db.AddWebAuthnCredential("AQID", "Key", []byte(`{"id":"AQID"}`))
	creds, _ := env.db.ListWebAuthnCredentials()
	wantCode(t, "delete bad", env.do("DELETE", "/admin/settings/passkeys/x", nil).Code, 400, "")
	if rec := env.do("DELETE", "/admin/settings/passkeys/"+itoa(creds[0].ID), nil); rec.Code != 200 {
		t.Errorf("delete passkey: %d", rec.Code)
	}
	if creds, _ := env.db.ListWebAuthnCredentials(); len(creds) != 0 {
		t.Error("passkey not deleted")
	}

	// Expired enrollment slot.
	env.h.pkEnroll.begin(nil, "x")
	env.h.pkEnroll.expires = time.Now().Add(-time.Second)
	if _, _, ok := env.h.pkEnroll.take(); ok {
		t.Error("expired enrollment should not be taken")
	}
}

func TestPasskeyLogin(t *testing.T) {
	env := newAdminEnv(t)
	_ = env.db.AddWebAuthnCredential("AQID", "Key", []byte(`{"id":"AQID"}`))

	post := func(path string, cookies ...*http.Cookie) *httptestRecorder {
		r := newReq(env, "POST", path, "{}")
		r.Host = "localhost"
		r.Header.Del("X-CSRF-Token")
		r.Header.Del("Cookie")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return serve(env, r)
	}
	if rec := post("/admin/login/webauthn/begin"); rec.Code != 400 {
		t.Errorf("begin without pending login = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish"); rec.Code != 400 {
		t.Errorf("finish without pending login = %d", rec.Code)
	}

	// The password step parks the login because a passkey is registered.
	rec := env.doWith("POST", "/admin/login", form("email", testAdminEmail, "password", testAdminPassword), "")
	pending := cookieByName(rec, twoFACookie)
	if pending == nil {
		t.Fatalf("password step should park the login: %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish", pending); rec.Code != 400 {
		t.Errorf("finish before begin = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/begin", pending); rec.Code != 200 || !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	for range maxLoginFailures {
		post("/admin/login/webauthn/begin", pending)
		post("/admin/login/webauthn/finish", pending)
	}
	if rec := post("/admin/login/webauthn/begin", pending); rec.Code != http.StatusTooManyRequests {
		t.Errorf("begin after lockout = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish", pending); rec.Code != http.StatusTooManyRequests {
		t.Errorf("finish after lockout = %d", rec.Code)
	}
}
