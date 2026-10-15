package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// TestBlockPageNegotiation is issue #111's "done when": a blocked browser
// gets a readable page carrying its request ID, an API client still JSON.
func TestBlockPageNegotiation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	h := newTestHandler(t, backend)
	e := echo.New()

	for _, tc := range []struct {
		name, accept string
		html         bool
	}{
		{"browser", "text/html,application/xhtml+xml,*/*;q=0.8", true},
		{"api", "application/json", false},
		{"no accept", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/?id=1'+OR+'1'='1", nil)
			req.Header.Set("X-Real-IP", "1.2.3.4")
			req.Header.Set("Accept", tc.accept)
			rec := httptest.NewRecorder()
			_ = h.Handle(e.NewContext(req, rec))

			id := rec.Header().Get("X-Request-ID")
			if rec.Code != http.StatusForbidden || id == "" {
				t.Fatalf("code = %d, request id = %q", rec.Code, id)
			}
			body := rec.Body.String()
			if tc.html {
				if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") ||
					!strings.Contains(body, id) || !strings.Contains(body, "Request blocked") {
					t.Errorf("block page missing request ID or title:\n%s", body)
				}
				if strings.Contains(body, "rule") && strings.Contains(body, "942") {
					t.Error("block page leaks the rule ID")
				}
				return
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not JSON: %v\n%s", err, body)
			}
			if got["error"] != "request blocked" || got["request_id"] != id {
				t.Errorf("JSON body = %v", got)
			}
		})
	}
}
