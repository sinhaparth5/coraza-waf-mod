package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

const testSession = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// runCSRF sends req through the csrfProtect middleware and reports whether it
// reached the handler and what status came back.
func runCSRF(t *testing.T, req *http.Request) (reached bool, status int) {
	t.Helper()
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := &Handler{}
	err := h.csrfProtect(func(echo.Context) error {
		reached = true
		return nil
	})(c)
	if err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return reached, he.Code
		}
		t.Fatalf("unexpected error type: %v", err)
	}
	return reached, http.StatusOK
}

func withSession(req *http.Request) *http.Request {
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testSession})
	return req
}

func TestCSRFTokenDerivation(t *testing.T) {
	a := csrfToken("session-a")
	if a != csrfToken("session-a") {
		t.Error("token must be deterministic per session")
	}
	if a == csrfToken("session-b") {
		t.Error("different sessions must get different tokens")
	}
	if a == "session-a" || strings.Contains(a, "session-a") {
		t.Error("token must not expose the session value")
	}
}

func TestCSRFAllowsSafeMethods(t *testing.T) {
	// No token anywhere — GET must still pass (read-only).
	req := withSession(httptest.NewRequest(http.MethodGet, "/admin/logs", nil))
	if reached, _ := runCSRF(t, req); !reached {
		t.Error("GET without token must not be blocked")
	}
}

func TestCSRFBlocksMutationsWithoutToken(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		req := withSession(httptest.NewRequest(method, "/admin/services", nil))
		reached, status := runCSRF(t, req)
		if reached || status != http.StatusForbidden {
			t.Errorf("%s without token: reached=%v status=%d, want blocked 403", method, reached, status)
		}
	}
}

func TestCSRFAcceptsHeaderToken(t *testing.T) {
	req := withSession(httptest.NewRequest(http.MethodPost, "/admin/services", nil))
	req.Header.Set(csrfHeader, csrfToken(testSession))
	if reached, status := runCSRF(t, req); !reached {
		t.Errorf("valid header token rejected (status %d)", status)
	}
}

func TestCSRFAcceptsFormToken(t *testing.T) {
	form := url.Values{csrfField: {csrfToken(testSession)}}
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/backup",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if reached, status := runCSRF(t, withSession(req)); !reached {
		t.Errorf("valid form token rejected (status %d)", status)
	}
}

func TestCSRFRejectsWrongOrForeignToken(t *testing.T) {
	// Token derived from a *different* session — what an attacker who has
	// their own account/session could compute.
	req := withSession(httptest.NewRequest(http.MethodPost, "/admin/services", nil))
	req.Header.Set(csrfHeader, csrfToken("some-other-session"))
	if reached, status := runCSRF(t, req); reached || status != http.StatusForbidden {
		t.Errorf("foreign token: reached=%v status=%d, want blocked 403", reached, status)
	}

	// No session cookie at all: nothing to derive from, must never pass.
	req = httptest.NewRequest(http.MethodPost, "/admin/services", nil)
	req.Header.Set(csrfHeader, csrfToken(""))
	if reached, status := runCSRF(t, req); reached || status != http.StatusForbidden {
		t.Errorf("no session: reached=%v status=%d, want blocked 403", reached, status)
	}
}
