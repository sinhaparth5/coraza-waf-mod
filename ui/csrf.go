package ui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/labstack/echo/v4"
)

// csrfHeader / csrfField are where a request may carry its CSRF token.
// HTMX requests get the header via hx-headers on <body> (base.html); plain
// HTML forms carry a hidden _csrf input.
const (
	csrfHeader = "X-CSRF-Token"
	csrfField  = "_csrf"
)

// csrfToken derives the CSRF token for a session. The token is a one-way
// hash of the session cookie value: it can't be forged without the cookie
// (256-bit random, HttpOnly) and, being non-invertible, embedding it in
// page HTML doesn't expose the session itself. Deriving instead of storing
// keeps this stateless — no extra table, survives restarts, and rotates
// automatically with every new session.
func csrfToken(sessionValue string) string {
	sum := sha256.Sum256([]byte("cz-csrf:" + sessionValue))
	return hex.EncodeToString(sum[:])
}

// csrfFromContext returns the CSRF token for the request's session, or ""
// when there is no session cookie (login page).
func (h *Handler) csrfFromContext(c echo.Context) string {
	ck, err := c.Cookie(sessionCookie)
	if err != nil || ck.Value == "" {
		return ""
	}
	return csrfToken(ck.Value)
}

// csrfProtect rejects state-changing requests that don't present the
// session's CSRF token. It runs after sessionAuth, so the session cookie is
// already known to be present and valid; SameSite=Lax alone is not enough
// because Lax still sends the cookie on top-level cross-site GET navigation
// and doesn't cover older/embedded clients.
func (h *Handler) csrfProtect(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		switch c.Request().Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return next(c)
		}

		expected := h.csrfFromContext(c)
		got := c.Request().Header.Get(csrfHeader)
		if got == "" {
			// Only fall back to the form for non-HTMX submissions; HTMX
			// always sends the header, so this parse only runs for the few
			// plain form-encoded posts.
			got = c.FormValue(csrfField)
		}
		if expected == "" || !hmac.Equal([]byte(expected), []byte(got)) {
			return echo.NewHTTPError(http.StatusForbidden,
				"invalid or missing CSRF token — reload the page and try again")
		}
		return next(c)
	}
}
