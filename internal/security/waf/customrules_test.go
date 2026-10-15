package waf

import (
	"strings"
	"testing"
)

func TestValidateCustomRule(t *testing.T) {
	for _, tc := range []struct {
		name, rule, wantErr string
		wantIDs             int
	}{
		{"ok", `SecRule ARGS "@contains evil" "id:1000001,phase:2,deny,status:403"`, "", 1},
		{"chain with continuation", "SecRule REQUEST_URI \"@beginsWith /x\" \"id:1000002,phase:1,deny,chain\"\nSecRule ARGS:id \\\n  \"@eq 1\"", "", 1},
		{"secaction", `SecAction "id:1000003,phase:1,pass,nolog"`, "", 1},
		{"crs id", `SecRule ARGS "@contains x" "id:942100,phase:2,deny"`, "outside the custom range", 0},
		{"no id", `SecRule ARGS "@contains x" "phase:2,deny"`, "needs an id", 0},
		{"include", `Include /etc/passwd`, "only SecRule", 0},
		{"engine off", "SecRuleEngine Off\nSecAction \"id:1000004,pass\"", "only SecRule", 0},
		{"does not compile", `SecRule ARGS "@nosuchop x" "id:1000005,deny"`, "nosuchop", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids, err := ValidateCustomRule(tc.rule)
			if tc.wantErr == "" {
				if err != nil || len(ids) != tc.wantIDs {
					t.Fatalf("ids=%v err=%v", ids, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
