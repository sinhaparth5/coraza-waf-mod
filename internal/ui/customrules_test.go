package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testCustomRule = `SecRule ARGS "@contains evil" "id:1000001,phase:2,deny,status:403"`

func TestCustomRuleHandlers(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")

	for _, tc := range []struct {
		name    string
		form    []string
		wantErr string
	}{
		{"empty", []string{"rules", " "}, "enter a rule"},
		{"crs id", []string{"rules", `SecRule ARGS "@contains x" "id:942100,deny"`}, "outside the custom range"},
		{"include", []string{"rules", "Include /etc/passwd"}, "only SecRule"},
		{"unknown service", []string{"rules", testCustomRule, "service", "nope"}, "no service named"},
		{"bad op, escaped", []string{"rules", `SecRule ARGS "@<b>x" "id:1000009,deny"`}, "&lt;b&gt;"},
	} {
		rec := env.do("POST", "/admin/waf-rules/custom", form(tc.form...))
		if rec.Header().Get("HX-Retarget") != "#custom-rule-error" || !strings.Contains(rec.Body.String(), tc.wantErr) {
			t.Errorf("%s: retarget=%q body=%q", tc.name, rec.Header().Get("HX-Retarget"), rec.Body.String())
		}
	}
	if n := env.count("waf"); n != 0 {
		t.Fatalf("rejected rules reloaded the WAF %d times", n)
	}

	rec := env.do("POST", "/admin/waf-rules/custom", form("rules", testCustomRule, "service", "shop", "note", "probe"))
	wantCode(t, "add", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "custom-rule-saved" || !strings.Contains(rec.Body.String(), "@contains evil") {
		t.Errorf("add response: trigger=%q", rec.Header().Get("HX-Trigger"))
	}
	rules, _ := env.db.ListWAFCustomRules()
	if len(rules) != 1 || !rules[0].Enabled || rules[0].ServiceName != "shop" || rules[0].Note != "probe" {
		t.Fatalf("rules = %+v", rules)
	}
	id := itoa(rules[0].ID)

	// Another rule can't reuse the id; the same rule can be edited in place.
	rec = env.do("POST", "/admin/waf-rules/custom", form("rules", testCustomRule))
	if !strings.Contains(rec.Body.String(), "already used by custom rule") {
		t.Errorf("duplicate id accepted: %q", rec.Body.String())
	}
	wantCode(t, "edit", env.do("POST", "/admin/waf-rules/custom", form("id", id, "rules", testCustomRule)).Code, 200, "")
	wantCode(t, "disable", env.do("POST", "/admin/waf-rules/custom/"+id+"/toggle", form()).Code, 200, "")
	rules, _ = env.db.ListWAFCustomRules()
	if len(rules) != 1 || rules[0].Enabled || rules[0].ServiceName != "" {
		t.Fatalf("after edit+disable = %+v", rules)
	}
	wantCode(t, "toggle bad", env.do("POST", "/admin/waf-rules/custom/x/toggle", form()).Code, 400, "")
	wantCode(t, "delete bad", env.do("DELETE", "/admin/waf-rules/custom/x", nil).Code, 400, "")
	wantCode(t, "delete", env.do("DELETE", "/admin/waf-rules/custom/"+id, nil).Code, 200, "")
	if rules, _ := env.db.ListWAFCustomRules(); len(rules) != 0 {
		t.Error("custom rule not deleted")
	}
	if n := env.count("waf"); n != 4 {
		t.Errorf("WAF reloads = %d, want 4 (add, edit, toggle, delete)", n)
	}
}

func TestAPICustomRules(t *testing.T) {
	h, e := newTestAPIHandler(t)
	h.reloadWAF = func() {}
	key := createTestKey(t, h, false)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	const base = "/admin/api/v1/waf-rules/custom"
	rule := `{"rule":"SecRule ARGS \"@contains evil\" \"id:1000001,phase:2,deny\""}`

	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", base, "{", 400},
		{"POST", base, `{"rule":"SecRuleEngine Off"}`, 400},
		{"POST", base, rule, 201},
		{"POST", base, rule, 400}, // id already used
		{"PUT", base + "/x", rule, 400},
		{"PUT", base + "/99999", `{"rule":"SecAction \"id:1000002,pass\""}`, 404},
		{"PUT", base + "/1", `{"rule":"SecRule ARGS \"@contains evil\" \"id:1000001,phase:2,deny\"","enabled":false,"note":"n"}`, 200},
		{"GET", base, "", 200},
		{"DELETE", base + "/x", "", 400},
		{"DELETE", base + "/1", "", 204},
	} {
		if rec := call(tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s %s %s = %d, want %d: %s", tc.method, tc.path, tc.body, rec.Code, tc.want, rec.Body.String())
		}
	}
	if rec := call("POST", base, rule); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"Enabled":true`) {
		t.Errorf("create response = %d %s", rec.Code, rec.Body.String())
	}
}
