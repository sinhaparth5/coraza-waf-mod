package ui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAPIValidation covers every 4xx branch of the REST API's write paths.
func TestAPIValidation(t *testing.T) {
	h, e := newTestAPIHandler(t)
	h.reloadWAF = func() {}
	key := createTestKey(t, h, false)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	if err := h.db.AddService("svc", "svc.example.com", "", backend.URL, 1, 2); err != nil {
		t.Fatal(err)
	}
	svcs, _ := h.db.ListServices()
	svc := fmt.Sprintf("/admin/api/v1/services/%d", svcs[0].ID)

	raw := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/admin/api/v1/services/x", "", 400},
		{"GET", "/admin/api/v1/services/99999", "", 404},
		{"POST", "/admin/api/v1/services", "{", 400},
		{"POST", "/admin/api/v1/services", `{"name":"x"}`, 400},
		{"POST", "/admin/api/v1/services", `{"name":"x","match_type":"host","match_value":"x.test","backend":"http://169.254.169.254"}`, 400},
		{"POST", "/admin/api/v1/services", `{"name":"x","match_type":"host","match_value":"x.test","backend":"http://127.0.0.1:1"}`, 400},
		{"PUT", "/admin/api/v1/services/x", `{}`, 400},
		{"PUT", "/admin/api/v1/services/99999", `{}`, 404},
		{"PUT", svc, "{", 400},
		{"PUT", svc, `{"backend":"http://169.254.169.254"}`, 400},
		{"PUT", svc, `{"name":" "}`, 400},
		{"PUT", svc, `{"bot_mode":"sometimes"}`, 400},
		{"PUT", svc, `{"schema_mode":"strict"}`, 400},
		{"PUT", svc, `{"schema_mode":"enforce","request_schema":"{\"type\":"}`, 400},
		{"PUT", svc, `{"host":"https://new.example.com/","prefix":"","backend":"` + backend.URL + `","rate_limit_rps":4,"rate_limit_burst":8,"bot_mode":"off","schema_mode":"log","request_schema":"{\"type\":\"object\"}"}`, 200},
		{"DELETE", "/admin/api/v1/services/x", "", 400},
		{"POST", "/admin/api/v1/ip-rules", "{", 400},
		{"POST", "/admin/api/v1/ip-rules", `{"ip":"1.2.3.4","rule_type":"maybe"}`, 400},
		{"POST", "/admin/api/v1/ip-rules", `{"ip":"nope","rule_type":"block"}`, 400},
		{"POST", "/admin/api/v1/ip-rules", `{"ip":"::ffff:1.2.3.4","rule_type":"block"}`, 201},
		{"POST", "/admin/api/v1/ip-rules", `{"ip":"2001:db8::1","rule_type":"allow"}`, 201},
		{"DELETE", "/admin/api/v1/ip-rules/x", "", 400},
		{"POST", "/admin/api/v1/bans", "{", 400},
		{"POST", "/admin/api/v1/bans", `{"ip":"nope"}`, 400},
		{"DELETE", "/admin/api/v1/bans/x", "", 400},
	} {
		if rec := raw(tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s %s %s = %d want %d: %s", tc.method, tc.path, tc.body, rec.Code, tc.want, rec.Body)
		}
	}

	got, _ := h.db.GetService(svcs[0].ID)
	if got.Host != "new.example.com" || got.RateLimitRPS != 4 || got.RateLimitBurst != 8 || got.BotMode != "off" || got.SchemaMode != "log" {
		t.Errorf("updated service = %+v", got)
	}
	rules, _ := h.db.ListIPRules()
	if len(rules) != 2 || rules[0].IP != "2001:db8::1" && rules[1].IP != "2001:db8::1" {
		t.Errorf("rules = %+v", rules)
	}
}

func TestCacheHelpers(t *testing.T) {
	if got := cacheRatio(0, 0); got != "—" {
		t.Errorf("cacheRatio(0,0) = %q", got)
	}
	if got := cacheRatio(3, 1); got != "75.0%" {
		t.Errorf("cacheRatio(3,1) = %q", got)
	}
	if got := fmtMiB(3 << 20); got != "3 MiB" {
		t.Errorf("fmtMiB = %q", got)
	}
}
