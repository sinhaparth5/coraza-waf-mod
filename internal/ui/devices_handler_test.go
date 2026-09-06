package ui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/security/geo"
	"coraza-waf-mod/internal/storage"
)

// TestRevokeDevice covers the three outcomes of the single row button: a
// still-live device is revoked (its row is kept, so it stays in the history
// and learns why it was signed out on its next request), an already
// signed-out one is dropped from the history entirely, and the caller's own
// device is left alone either way.
func TestRevokeDevice(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	h := &Handler{
		cfg:   &config.Config{Admin: config.AdminConfig{Path: "/admin"}},
		db:    db,
		geoBl: &geo.Blocker{}, // no mmdb loaded: every lookup returns ""
	}
	if err := h.parseTemplates(); err != nil {
		t.Fatal(err)
	}

	// del issues the DELETE the row button sends, as the given caller.
	del := func(t *testing.T, caller, target string) {
		t.Helper()
		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/admin/settings/devices/"+target, nil)
		if caller != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: caller})
		}
		c := e.NewContext(req, httptest.NewRecorder())
		c.SetParamNames("token")
		c.SetParamValues(target)
		if err := h.RevokeDevice(c); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("live device is revoked, not deleted", func(t *testing.T) {
		target, err := db.CreateSession("10.0.0.1", "curl/8.5.0")
		if err != nil {
			t.Fatal(err)
		}
		del(t, "some-other-session", target)

		sess, err := db.GetSession(target)
		if err != nil {
			t.Fatal(err)
		}
		if sess == nil {
			t.Fatal("row was deleted; a live device must be revoked so it keeps its history entry")
		}
		if !sess.Revoked() || sess.Live() {
			t.Errorf("revoked=%v live=%v, want revoked and not live", sess.Revoked(), sess.Live())
		}
	})

	t.Run("signed-out device is dropped from the history", func(t *testing.T) {
		stale, err := db.CreateSession("10.0.0.2", "curl/8.5.0")
		if err != nil {
			t.Fatal(err)
		}
		mine, err := db.CreateSession("10.0.0.3", "curl/8.5.0") // revokes stale
		if err != nil {
			t.Fatal(err)
		}
		if sess, _ := db.GetSession(stale); sess == nil || sess.Live() {
			t.Fatal("precondition: stale should exist and be signed out")
		}

		del(t, mine, stale)

		sess, err := db.GetSession(stale)
		if err != nil {
			t.Fatal(err)
		}
		if sess != nil {
			t.Error("signed-out row survived; the button should forget it")
		}
		if valid, _ := db.ValidateSession(mine); !valid {
			t.Error("caller's own session was affected")
		}
	})

	t.Run("current device is never touched", func(t *testing.T) {
		mine, err := db.CreateSession("10.0.0.4", "curl/8.5.0")
		if err != nil {
			t.Fatal(err)
		}
		del(t, mine, mine)

		if valid, _ := db.ValidateSession(mine); !valid {
			t.Error("caller signed itself out via the device list")
		}
	})
}
