package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// TestResolveDBConnInput exercises the "Database connection" Settings
// card's form-parsing/validation logic directly — the branching between
// sqlite (host doubles as file path, no dialect fields at all), a pasted
// DSN, and individually-filled fields is real logic worth covering, even
// though the card's HTTP handlers themselves aren't otherwise tested beyond
// template rendering (dbconn_template_test.go), matching this codebase's
// existing coverage level for Settings-page save/test handlers.
func TestResolveDBConnInput(t *testing.T) {
	e := echo.New()
	newCtx := func(form url.Values) echo.Context {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return e.NewContext(req, httptest.NewRecorder())
	}

	t.Run("missing driver errors", func(t *testing.T) {
		if _, _, err := resolveDBConnInput(newCtx(url.Values{})); err == nil {
			t.Error("want error for missing driver")
		}
	})

	t.Run("sqlite uses host as the file path", func(t *testing.T) {
		driver, dsn, err := resolveDBConnInput(newCtx(url.Values{
			"dbconn_driver": {"sqlite"}, "dbconn_host": {"/data/waf.db"},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if driver != "sqlite" || dsn != "/data/waf.db" {
			t.Errorf("got driver=%q dsn=%q, want sqlite /data/waf.db", driver, dsn)
		}
	})

	t.Run("sqlite missing path errors", func(t *testing.T) {
		if _, _, err := resolveDBConnInput(newCtx(url.Values{"dbconn_driver": {"sqlite"}})); err == nil {
			t.Error("want error for missing sqlite path")
		}
	})

	t.Run("dsn mode uses the raw connection string verbatim", func(t *testing.T) {
		want := "postgres://u:p@host:5432/db?sslmode=require"
		driver, dsn, err := resolveDBConnInput(newCtx(url.Values{
			"dbconn_driver": {"postgres"}, "dbconn_mode": {"dsn"}, "dbconn_dsn": {want},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if driver != "postgres" || dsn != want {
			t.Errorf("got driver=%q dsn=%q, want postgres %q", driver, dsn, want)
		}
	})

	t.Run("dsn mode blank errors", func(t *testing.T) {
		if _, _, err := resolveDBConnInput(newCtx(url.Values{
			"dbconn_driver": {"postgres"}, "dbconn_mode": {"dsn"},
		})); err == nil {
			t.Error("want error for blank connection string")
		}
	})

	t.Run("fields mode missing host errors", func(t *testing.T) {
		if _, _, err := resolveDBConnInput(newCtx(url.Values{"dbconn_driver": {"mysql"}})); err == nil {
			t.Error("want error for missing host")
		}
	})

	t.Run("fields mode builds a DSN via storage.BuildDSN", func(t *testing.T) {
		driver, dsn, err := resolveDBConnInput(newCtx(url.Values{
			"dbconn_driver": {"mysql"}, "dbconn_host": {"db"}, "dbconn_port": {"3307"},
			"dbconn_username": {"root"}, "dbconn_password": {"secret"}, "dbconn_dbname": {"coraza"},
		}))
		if err != nil {
			t.Fatal(err)
		}
		if driver != "mysql" || !strings.Contains(dsn, "tcp(db:3307)") || !strings.Contains(dsn, "coraza") {
			t.Errorf("got driver=%q dsn=%q, want a mysql DSN for db:3307/coraza", driver, dsn)
		}
	})
}
