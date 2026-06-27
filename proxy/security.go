package proxy

import "github.com/labstack/echo/v4"

// SecurityMiddleware sets hardening HTTP headers on every response:
// standard browser security directives plus Coraza WAF identification headers.
// Applied globally so blocked responses, admin UI pages, and proxied responses
// all carry the same baseline security posture.
func SecurityMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			h := c.Response().Header()

			// ── Browser hardening ─────────────────────────────────────────────────
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "SAMEORIGIN")
			h.Set("X-XSS-Protection", "1; mode=block")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy",
				"camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")

			// HSTS: only advertise over TLS to avoid breaking plain-HTTP dev setups.
			// 63072000 s = 2 years, matching hstspreload.org recommendations.
			if c.Request().TLS != nil {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}

			// ── Coraza WAF identification ─────────────────────────────────────────
			h.Set("X-Protected-By", "Coraza WAF Mod")
			h.Set("X-WAF-Engine", "Coraza v3 / OWASP CRS")

			return next(c)
		}
	}
}

// BackendSecurityHeaders is the set of security response headers we own.
// The services registry's ModifyResponse hook deletes these from backend
// responses so the WAF-set versions are the only ones the client sees —
// no duplicates when the backend also sets them.
var BackendSecurityHeaders = []string{
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-XSS-Protection",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Strict-Transport-Security",
}
