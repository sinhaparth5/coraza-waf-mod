package proxy

import (
	"context"
	"log"
	"net/http"
	"time"

	"coraza-waf-mod/internal/storage"

	"github.com/labstack/echo/v4"
)

// RegisterProbes adds the liveness and readiness probes used by load
// balancers, orchestrators and the Docker HEALTHCHECK (#1). They are
// unauthenticated and served on every host, so they answer "ok" or not and
// nothing more. Readiness checks only the DB: one dead backend must not pull
// the whole WAF out of a load balancer.
func RegisterProbes(e *echo.Echo, db *storage.DB) {
	probe := []string{http.MethodGet, http.MethodHead}
	e.Match(probe, "/_cz/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	e.Match(probe, "/_cz/readyz", func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			log.Printf("readyz: db ping: %v", err)
			return c.String(http.StatusServiceUnavailable, "db unavailable")
		}
		return c.String(http.StatusOK, "ok")
	})
}
