package ui

import (
	"embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"palisade/internal/config"
	"palisade/internal/security/blocklist"
	"palisade/internal/security/challenge"
	"palisade/internal/security/geo"
	"palisade/internal/security/threatscore"
	"palisade/internal/services"
	"palisade/internal/storage"
)

// adminEnv is a fully wired admin UI — the real NewHandler and Register —
// over a temp SQLite DB, plus a logged-in session. Callback hooks count
// their invocations so tests can assert a save actually triggered a reload.
type adminEnv struct {
	t       *testing.T
	h       *Handler
	e       *echo.Echo
	db      *storage.DB
	session string
	calls   map[string]*atomic.Int32
	backend *httptest.Server
}

const testAdminEmail, testAdminPassword = "admin@example.com", "correct horse battery"

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.SeedAdmin(testAdminEmail, testAdminPassword); err != nil {
		t.Fatal(err)
	}
	reg, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}
	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}
	geoBl, err := geo.New("", db)
	if err != nil {
		t.Fatal(err)
	}

	env := &adminEnv{t: t, db: db, calls: map[string]*atomic.Int32{}}
	hook := func(name string) func() {
		env.calls[name] = &atomic.Int32{}
		return func() { env.calls[name].Add(1) }
	}
	reloadRL, reloadWAF, reloadAutoban, reloadAdaptive := hook("ratelimit"), hook("waf"), hook("autoban"), hook("adaptive")
	syncIntel, report, webhook, loginCode, reloadBot := hook("intel"), hook("report"), hook("webhook"), hook("logincode"), hook("bot")

	cfg := config.Defaults()
	h, err := NewHandler(cfg, db, ipbl, geoBl, reg, NewLogBroadcaster(),
		embed.FS{}, embed.FS{}, embed.FS{},
		func(*challenge.Challenger) { reloadBot() },
		func(enabled bool, threshold, ttl int) *challenge.Challenger { return nil },
		reloadRL, reloadWAF,
		func(int64) { syncIntel() },
		func() error { report(); return nil },
		func() error { webhook(); return nil },
		func(string) error { loginCode(); return nil },
		reloadAutoban,
		threatscore.New(db, func(string) int { return 0 }),
		reloadAdaptive,
		func(c echo.Context) error { return c.String(http.StatusTeapot, "proxied") },
	)
	if err != nil {
		t.Fatal(err)
	}
	env.h = h
	env.e = echo.New()
	h.Register(env.e)
	h.RegisterAPI(env.e)

	env.session, err = db.CreateSession("127.0.0.1", "test", "")
	if err != nil {
		t.Fatal(err)
	}

	env.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(env.backend.Close)
	return env
}

// do sends an authenticated admin request (session cookie + CSRF header).
func (env *adminEnv) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	env.t.Helper()
	return env.doWith(method, path, form, env.session)
}

func (env *adminEnv) doWith(method, path string, form url.Values, session string) *httptest.ResponseRecorder {
	env.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "127.0.0.1:12345"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		req.Header.Set("X-CSRF-Token", csrfToken(session))
	}
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
}

func (env *adminEnv) count(name string) int32 { return env.calls[name].Load() }

// seedService adds a service pointing at the env's live test backend.
func (env *adminEnv) seedService(name, host string) storage.Service {
	env.t.Helper()
	if err := env.db.AddService(name, host, "", env.backend.URL, 0, 0); err != nil {
		env.t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		env.t.Fatal(err)
	}
	svcs, _ := env.db.ListServices()
	for _, s := range svcs {
		if s.Name == name {
			return s
		}
	}
	env.t.Fatalf("service %q not found", name)
	return storage.Service{}
}

func (env *adminEnv) seedLog(r storage.RequestLog) int64 {
	env.t.Helper()
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	id, err := env.db.InsertRequest(r)
	if err != nil {
		env.t.Fatal(err)
	}
	return id
}

func form(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

type httptestRecorder = httptest.ResponseRecorder

// newReq builds an authenticated request with a raw (JSON) body.
func newReq(env *adminEnv, method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
	req.Header.Set("X-CSRF-Token", csrfToken(env.session))
	return req
}

func serve(env *adminEnv, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
}
