// Regenerates static/js/dist/*.min.js from static/js/src/*.js before build.
// `make build` runs this automatically; if running `go build` directly,
// run `go generate ./...` first after editing any source JS file.
//go:generate go run ./tools/minify

package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"coraza-waf-mod/asn"
	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/challenge"
	"coraza-waf-mod/config"
	"coraza-waf-mod/geo"
	ja3pkg "coraza-waf-mod/ja3"
	"coraza-waf-mod/metrics"
	"coraza-waf-mod/proxy"
	"coraza-waf-mod/ratelimit"
	"coraza-waf-mod/services"
	"coraza-waf-mod/storage"
	"coraza-waf-mod/ui"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	args := os.Args[1:]

	// `coraza-waf-mod prune [config.yaml]` opens just the DB, deletes logs
	// older than the configured retention window, and exits — meant to be
	// invoked by an external scheduler (cron, or a systemd timer; see
	// deploy/coraza-waf-mod-prune.{service,timer}) instead of running inside
	// the long-lived server process, so a multi-second batched delete never
	// has to share that process's DB connection pool with live traffic.
	if len(args) > 0 && args[0] == "prune" {
		cfgPath := "config.yaml"
		if len(args) > 1 {
			cfgPath = args[1]
		}
		runPruneOnly(cfgPath)
		return
	}

	cfgPath := "config.yaml"
	if len(args) > 0 {
		cfgPath = args[0]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	// buildWAF constructs a fresh engine reading the current disabled-rule list
	// from the DB each time, so SIGHUP and the WAF Rules UI page both pick up
	// the latest toggles without a restart.
	buildWAF := func() (*waf.Engine, error) {
		disabledIDs, _ := db.GetDisabledWAFRuleIDs()
		return waf.New(cfg.WAF, disabledIDs)
	}

	engine, err := buildWAF()
	if err != nil {
		log.Fatalf("waf init: %v", err)
	}

	if err := db.SeedTestAdmin(); err != nil {
		log.Fatalf("seed admin: %v", err)
	}
	log.Printf("admin login: admin@localhost / admin123  (change after first login)")

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		log.Fatalf("ip blocklist: %v", err)
	}

	geoBl, err := geo.New(cfg.Geo.DBPath, db)
	if err != nil {
		log.Fatalf("geo blocker: %v", err)
	}
	defer geoBl.Close()

	// Choose rate-limit backend: Redis (multi-node) or in-process Limiter
	// with SQLite write-back persistence (single-node, survives restarts).
	redisAddr, redisPwd, _ := db.GetRedisConfig()
	rl := buildRateLimit(cfg, db, redisAddr, redisPwd)
	defer rl.Stop()

	asnLookup, err := asn.New()
	if err != nil {
		log.Printf("asn: failed to load ASN database, ASN/org lookup disabled: %v", err)
		asnLookup = nil
	} else {
		defer asnLookup.Close()
	}

	// One-time migration: legacy config.yaml apps: entries become rows in
	// the services table, so the admin Services page is the source of
	// truth going forward.
	legacyApps := make([]storage.ConfigApp, len(cfg.Apps))
	for i, a := range cfg.Apps {
		legacyApps[i] = storage.ConfigApp{Name: a.Name, Host: a.Host, Prefix: a.Prefix, Backend: a.Backend}
	}
	if err := db.MigrateConfigApps(legacyApps); err != nil {
		log.Fatalf("migrate config apps: %v", err)
	}

	registry, err := services.New(db)
	if err != nil {
		log.Fatalf("services registry: %v", err)
	}
	metrics.SetDB(db)
	metrics.SetRegistry(registry)
	metrics.SetLimiter(rl)

	broadcaster := ui.NewLogBroadcaster()
	// Wire broadcaster into the DB log worker so every insert is pushed to the
	// SSE stream with the real row ID, not a zero placeholder.
	db.SetBroadcastFn(broadcaster.Broadcast)

	// Bot protection: DB is the source of truth (managed via Settings page).
	// config.yaml BotProtection fields are only used as fallback defaults on
	// first startup before the user has touched the Settings page.
	botEnabled, botThreshold, botTTL, _ := db.GetBotSettings()
	// If the DB has never been configured, seed from config.yaml defaults.
	if !botEnabled && cfg.BotProtection.Enabled {
		botEnabled = cfg.BotProtection.Enabled
		botThreshold = cfg.BotProtection.AnomalyThreshold
		botTTL = cfg.BotProtection.ChallengeTTLSeconds
	}

	secret, err := db.GetOrCreateChallengeSecret()
	if err != nil {
		log.Fatalf("challenge secret: %v", err)
	}

	buildChallenger := func(enabled bool, threshold, ttl int) *challenge.Challenger {
		if !enabled {
			return nil
		}
		return challenge.New(secret, ttl, threshold)
	}

	var ch *challenge.Challenger
	if botEnabled {
		ch = buildChallenger(true, botThreshold, botTTL)
		log.Printf("bot protection enabled (threshold=%d, ttl=%ds)", botThreshold, botTTL)
	}

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:    true,
		LogStatus: true,
		LogMethod: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			log.Printf("%s %s -> %d", v.Method, v.URI, v.Status)
			return nil
		},
	}))

	h := proxy.NewHandler(registry, engine, db, ipbl, geoBl, rl, asnLookup, ch)

	// reloadWAF rebuilds the WAF engine from the current DB disabled-rule list.
	// Called from the WAF Rules page when a rule is toggled.
	reloadWAF := func() {
		newEngine, err := buildWAF()
		if err != nil {
			log.Printf("waf reload: %v", err)
			return
		}
		h.ReloadWAF(newEngine)
	}

	// reloadBot is called from the Settings page when bot protection config changes.
	reloadBot := func(newCh *challenge.Challenger) {
		h.ReloadBotProtection(newCh)
	}

	// reloadRateLimit is called from the Settings page when the rate-limit
	// backend config changes. Reads the current DB config and hot-swaps
	// the backend in the proxy handler — no restart needed.
	reloadRateLimit := func() {
		addr, pwd, _ := db.GetRedisConfig()
		newBackend := buildRateLimit(cfg, db, addr, pwd)
		h.ReloadRateLimit(newBackend)
	}

	uiHandler, err := ui.NewHandler(cfg, db, ipbl, geoBl, registry, broadcaster, staticJS, staticImgs, reloadBot, buildChallenger, reloadRateLimit, reloadWAF)
	if err != nil {
		log.Fatalf("ui init: %v", err)
	}
	uiHandler.Register(e)

	// Challenge routes must be registered before the catch-all proxy route so
	// Echo routes them to the challenger, not the backend.
	e.GET("/_cz/challenge", func(c echo.Context) error {
		h.ServeChallengePage(c.Response().Writer, c.Request())
		return nil
	})
	e.POST("/_cz/verify", func(c echo.Context) error {
		h.ServeChallengeVerify(c.Response().Writer, c.Request())
		return nil
	})

	e.Any("/*", h.Handle)

	// SIGHUP: reload the WAF engine (picks up changes to rules_dir) without
	// restarting. Services hot-reload on every UI change via registry.Reload,
	// so SIGHUP is only needed for WAF rule updates.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		for range sigCh {
			log.Printf("SIGHUP: reloading WAF engine...")
			newEngine, err := buildWAF()
			if err != nil {
				log.Printf("SIGHUP: WAF reload failed, keeping existing engine: %v", err)
				continue
			}
			h.ReloadWAF(newEngine)
		}
	}()

	appCount := len(registry.List())

	// TLS only starts when listen_addr_tls is explicitly set in config.yaml.
	// Certificate config (ACME email, per-service certs) lives entirely in the DB.
	if cfg.ListenAddrTLS != "" {
		startTLS(e, cfg, registry, db, appCount)
		return
	}
	log.Printf("coraza-waf listening on %s (plain HTTP, waf=%v, apps=%d)",
		cfg.ListenAddr, cfg.WAF.Enabled, appCount)
	if err := e.Start(cfg.ListenAddr); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// startTLS is the single entry point for HTTPS. It reads the ACME contact
// email from the DB (not config.yaml), builds an autocert manager if present,
// then starts HTTP on cfg.ListenAddr (ACME challenge handler + HTTPS redirect)
// and HTTPS on cfg.ListenAddrTLS. Per-service custom certs take priority over
// autocert by SNI (see services.Registry.GetCertificateFunc).
func startTLS(e *echo.Echo, cfg *config.Config, registry *services.Registry, db *storage.DB, appCount int) {
	email, _ := db.GetAcmeEmail()

	var am *autocert.Manager
	if email != "" {
		if err := os.MkdirAll(cfg.TLS.CacheDir, 0700); err != nil {
			log.Fatalf("cannot create cert cache dir %s: %v", cfg.TLS.CacheDir, err)
		}
		am = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: registry.HostPolicy(),
			Cache:      autocert.DirCache(cfg.TLS.CacheDir),
			Email:      email,
		}
	}

	// HTTP: ACME HTTP-01 challenge handler (if autocert active) + HTTPS redirect.
	var httpHandler http.Handler = http.HandlerFunc(httpsRedirect)
	if am != nil {
		httpHandler = am.HTTPHandler(httpHandler)
	}
	go func() {
		log.Printf("coraza-waf HTTP (ACME/redirect) on %s", cfg.ListenAddr)
		srv := &http.Server{Addr: cfg.ListenAddr, Handler: httpHandler}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	s := e.TLSServer
	s.Addr = cfg.ListenAddrTLS

	getCert := registry.GetCertificateFunc(am)
	s.TLSConfig = &tls.Config{
		GetCertificate: getCert,
		// Capture the ClientHello so we can compute a JA3 fingerprint for each
		// connection. The hash is stored in ja3pkg's sync.Map keyed by remoteAddr
		// and retrieved later in the proxy handler when the HTTP request arrives.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			hash := ja3pkg.Compute(hello)
			if hash != "" {
				ja3pkg.Store(hello.Conn.RemoteAddr().String(), hash)
			}
			return nil, nil
		},
	}

	log.Printf("coraza-waf TLS on %s (waf=%v, apps=%d)", cfg.ListenAddrTLS, cfg.WAF.Enabled, appCount)
	if err := e.StartServer(s); err != nil {
		log.Fatalf("tls server: %v", err)
	}
}

// runPruneOnly opens the DB, deletes request logs older than the configured
// retention window, logs the result, and returns — it does not start the WAF,
// proxy, or admin UI. retentionDays <= 0 disables pruning (logs kept forever).
func runPruneOnly(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.DB.LogRetentionDays <= 0 {
		log.Printf("log retention: disabled (log_retention_days <= 0), nothing to prune")
		return
	}

	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	start := time.Now()
	n, err := db.PruneOldRequests(cfg.DB.LogRetentionDays)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("log retention: prune failed after %s: %v", dur, err)
	}
	log.Printf("log retention: deleted %d requests older than %d days (took %s)", n, cfg.DB.LogRetentionDays, dur)
}

func httpsRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// buildRateLimit creates the appropriate rate-limit backend.
// When redisAddr is non-empty, it tries Redis (multi-node); on failure or when
// empty, it falls back to the in-process Limiter with SQLite write-back
// persistence so token-bucket state survives restarts.
func buildRateLimit(cfg *config.Config, db *storage.DB, redisAddr, redisPwd string) ratelimit.Backend {
	if redisAddr != "" {
		rb, err := ratelimit.NewRedisBackend(redisAddr, redisPwd, cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst)
		if err != nil {
			log.Printf("rate limit: redis connect failed (%v), falling back to in-memory+SQLite", err)
		} else {
			log.Printf("rate limit: using Redis backend at %s", redisAddr)
			return rb
		}
	}
	l := ratelimit.New(cfg.RateLimit)
	if states, err := db.LoadRateLimitState(); err == nil && len(states) > 0 {
		l.RestoreFrom(states)
		log.Printf("rate limit: restored %d buckets from SQLite", len(states))
	}
	l.StartPersistence(db)
	return l
}
