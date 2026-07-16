// Regenerates static/js/dist/*.min.js from static/js/src/*.js before build.
// `make build` runs this automatically; if running `go build` directly,
// run `go generate ./...` first after editing any source JS file.
//go:generate go run ./tools/minify

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"coraza-waf-mod/internal/config"
	"coraza-waf-mod/internal/notify/accesslog"
	"coraza-waf-mod/internal/notify/mailer"
	"coraza-waf-mod/internal/notify/metrics"
	"coraza-waf-mod/internal/notify/webhook"
	"coraza-waf-mod/internal/proxy"
	"coraza-waf-mod/internal/security/adaptive"
	"coraza-waf-mod/internal/security/asn"
	"coraza-waf-mod/internal/security/autoban"
	"coraza-waf-mod/internal/security/blocklist"
	"coraza-waf-mod/internal/security/challenge"
	"coraza-waf-mod/internal/security/geo"
	ja3pkg "coraza-waf-mod/internal/security/ja3"
	ja4pkg "coraza-waf-mod/internal/security/ja4"
	"coraza-waf-mod/internal/security/ratelimit"
	"coraza-waf-mod/internal/security/threatintel"
	"coraza-waf-mod/internal/security/threatscore"
	"coraza-waf-mod/internal/security/waf"
	"coraza-waf-mod/internal/services"
	"coraza-waf-mod/internal/storage"
	"coraza-waf-mod/internal/ui"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/acme/autocert"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "version":
			fmt.Println("coraza-waf-mod", version)
			return
		case "prune":
			runPruneOnly(os.Args[2:])
			return
		case "setup":
			runSetup(os.Args[2:])
			return
		case "gencert":
			runGencert(os.Args[2:])
			return
		case "build-dsn":
			runBuildDSN(os.Args[2:])
			return
		}
	}

	// CLI flags for bootstrap settings. All runtime knobs (WAF rules, bot
	// protection, Redis, ACME email, per-service overrides) live in the SQLite
	// meta table and are managed from the admin UI — no config file needed.
	fs := flag.NewFlagSet("coraza-waf-mod", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	listenTLS := fs.String("listen-tls", "", "HTTPS listen address (empty = HTTP only)")
	trustedProxies := fs.String("trusted-proxies", "", "comma-separated trusted proxy CIDRs for X-Forwarded-For/X-Real-IP")
	dbPath := fs.String("db", "waf.db", "database path (sqlite) or DSN (mysql/postgres)")
	dbDriver := fs.String("db-driver", "sqlite", "database driver: sqlite, mysql (or mariadb), postgres (or postgresql/cockroachdb/neon)")
	certsDir := fs.String("certs", "./certs", "TLS certificate cache directory")
	wafRules := fs.String("waf-rules", "", "extra WAF rules directory (empty = OWASP CRS only)")
	geoDBPath := fs.String("geo-db", "", "GeoIP2 database path (empty = bundled)")
	retention := fs.Int("retention", 30, "request log retention in days (0 = keep forever)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate file for HTTPS fallback (self-signed)")
	tlsKey := fs.String("tls-key", "", "PEM private key file for HTTPS fallback (self-signed)")
	accessLogPath := fs.String("access-log", "", "nginx-style access log file path (empty = disabled)")
	accessLogMaxSizeMB := fs.Int("access-log-max-size-mb", 100, "rotate access log after this many MB")
	accessLogMaxBackups := fs.Int("access-log-max-backups", 5, "number of rotated access log files to keep")
	dbKeyFile := fs.String("db-key-file", "", "key file for AES-256-GCM encryption of stored secrets at rest (empty = plaintext)")
	fs.Parse(os.Args[1:]) //nolint // ExitOnError: never returns an error to check

	cfg := config.Defaults()
	cfg.ListenAddr = *listen
	cfg.ListenAddrTLS = *listenTLS
	cfg.TrustedProxies = splitCSV(*trustedProxies)
	cfg.DB.Path = *dbPath
	cfg.DB.Driver = *dbDriver
	cfg.TLS.CacheDir = *certsDir
	cfg.TLS.FallbackCertFile = *tlsCert
	cfg.TLS.FallbackKeyFile = *tlsKey
	cfg.WAF.RulesDir = *wafRules
	cfg.Geo.DBPath = *geoDBPath
	cfg.DB.LogRetentionDays = *retention

	db, err := storage.OpenWithDriver(cfg.DB.Driver, cfg.DB.Path)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	// Must happen before anything reads secret config (the challenge secret,
	// TOTP secrets, email/webhook/Redis credentials) — EnableSecretEncryption
	// also migrates any still-plaintext secrets, so first boot with a key
	// needs no manual step.
	if *dbKeyFile != "" {
		if err := enableDBEncryption(db, *dbKeyFile); err != nil {
			log.Fatalf("db-key-file: %v", err)
		}
		log.Printf("secrets-at-rest encryption enabled (key file %s)", *dbKeyFile)
	}

	// buildWAFAll constructs a fresh default engine plus one extra engine per
	// service that has its own rule exceptions, reading the current DB state
	// each time, so SIGHUP and the WAF Rules UI page both pick up the latest
	// toggles without a restart. Only services with at least one row in
	// waf_service_rule_exceptions get an extra engine — a deployment that
	// never uses per-service exceptions pays zero extra memory for this
	// (each engine holds the full compiled OWASP CRS ruleset, so this is
	// deliberately lazy rather than always building one per service).
	buildWAFAll := func() (*waf.Engine, map[string]*waf.Engine, error) {
		globalIDs, err := db.GetDisabledWAFRuleIDs()
		if err != nil {
			return nil, nil, err
		}
		defaultEngine, err := waf.New(cfg.WAF, globalIDs)
		if err != nil {
			return nil, nil, err
		}

		svcNames, err := db.ListWAFExceptionServiceNames()
		if err != nil {
			return nil, nil, err
		}
		byService := make(map[string]*waf.Engine, len(svcNames))
		for _, name := range svcNames {
			svcIDs, err := db.GetWAFRuleIDsForService(name)
			if err != nil {
				return nil, nil, err
			}
			merged := append(append([]int{}, globalIDs...), svcIDs...)
			eng, err := waf.New(cfg.WAF, merged)
			if err != nil {
				return nil, nil, err
			}
			byService[name] = eng
		}
		return defaultEngine, byService, nil
	}

	engine, wafByService, err := buildWAFAll()
	if err != nil {
		log.Fatalf("waf init: %v", err)
	}

	// No default credentials are ever seeded — a publicly-known fallback
	// login would hand over the whole WAF on any deploy that skipped setup.
	// The WAF/proxy still runs without an admin (login rejects everything);
	// only the dashboard is unusable until credentials are created.
	if email, _ := db.GetAdminEmail(); email == "" {
		log.Printf("no admin credentials configured — admin UI logins will be rejected until you run:")
		log.Printf("  coraza-waf-mod setup --db %s --admin-email you@example.com  (password read from stdin)", cfg.DB.Path)
	}

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		log.Fatalf("ip blocklist: %v", err)
	}

	reloadIntel := func() {
		if err := ipbl.ReloadIntel(db); err != nil {
			log.Printf("threat-intel: blocklist reload: %v", err)
		}
	}
	intelWorker := threatintel.New(db, reloadIntel)
	defer intelWorker.Stop()

	geoBl, err := geo.New(cfg.Geo.DBPath, db)
	if err != nil {
		log.Fatalf("geo blocker: %v", err)
	}
	defer geoBl.Close()

	// Choose rate-limit backend: Redis (multi-node) or in-process Limiter
	// with SQLite write-back persistence (single-node, survives restarts).
	redisAddr, redisPwd, _ := db.GetRedisConfig()
	rl := buildRateLimit(db, redisAddr, redisPwd)

	asnLookup, err := asn.New()
	if err != nil {
		log.Printf("asn: failed to load ASN database, ASN/org lookup disabled: %v", err)
		asnLookup = nil
	} else {
		defer asnLookup.Close()
	}

	// One-time migration marker: no config file to migrate from, but we still
	// need to set the "already migrated" flag so the DB doesn't wait for it.
	if err := db.MigrateConfigApps(nil); err != nil {
		log.Fatalf("migrate config apps: %v", err)
	}

	registry, err := services.New(db)
	if err != nil {
		log.Fatalf("services registry: %v", err)
	}

	// Cache-return listener: the single static backend the Varnish VCL points
	// at. Varnish fetches cache misses here and the registry routes them to
	// the right backend, so adding/editing services never touches the VCL.
	// Always started (even with the integration toggled off) so enabling
	// Varnish from the Settings page needs no restart; it only ever binds
	// loopback and serves nothing unless Varnish sends traffic.
	go startCacheReturn(db, registry)

	metrics.SetDB(db)
	metrics.SetRegistry(registry)
	metrics.SetLimiter(rl)

	broadcaster := ui.NewLogBroadcaster()
	// Wire broadcaster into the DB log worker so every insert is pushed to the
	// SSE stream with the real row ID, not a zero placeholder.
	db.SetBroadcastFn(broadcaster.Broadcast)

	// Webhook pusher: delivers security events to the configured endpoint
	// asynchronously so a slow webhook never blocks the log worker.
	webhookPusher := webhook.New(db.GetWebhookConfig)
	defer webhookPusher.Stop()
	db.SetWebhookFn(webhookPusher.Push)

	// Daily report email: crunches the previous day's blocked/403 counts just
	// after local midnight and mails them via the SMTP settings stored in the
	// DB (managed from the Settings page — never shipped in config or binary).
	emailReporter := mailer.NewReporter(db)
	defer emailReporter.Stop()

	// Automatic IP banning: scores blocked events per client IP from the log
	// stream and turns repeat offenders / severe attackers into permanent
	// global block rules, hot-reloading the blocklist and emailing the admin.
	banner := autoban.New(db, func() {
		if err := ipbl.Reload(db); err != nil {
			log.Printf("autoban: blocklist reload: %v", err)
		}
	}, func(ip, reason string) {
		if err := emailReporter.SendBanAlert(ip, reason); err != nil {
			log.Printf("autoban: ban alert email for %s: %v", ip, err)
		}
	})
	defer banner.Stop()
	db.SetAutobanFn(banner.Record)

	// Unified per-IP threat score: a composite read model (issue #12)
	// combining autoban's history, bot score, ASN/hosting classification,
	// geo risk, and JA4 repeat-offender history.
	scorer := threatscore.New(db, banner.Score)
	defer scorer.Stop()
	if rules, err := db.ListGeoRules(); err != nil {
		log.Printf("threatscore: initial geo rules load: %v", err)
	} else {
		scorer.ReloadGeoRules(rules)
	}
	db.SetThreatScoreFn(scorer.Record)

	// Threat-score-driven adaptive enforcement (issue #16): scales the
	// global rate limit and can force a bot challenge based on a client's
	// current composite score. Disabled by default — opt in from the IP
	// Rules page once real scores are visible there.
	adaptivePolicy := adaptive.New(db)

	// nginx-style access.log: opt-in flat-file log for tooling that expects
	// one (fail2ban, log shippers, grep/awk, logrotate) — independent of the
	// SQLite-backed admin UI logging above. Disabled unless --access-log is set.
	if *accessLogPath != "" {
		accessLogWriter, err := accesslog.New(*accessLogPath, *accessLogMaxSizeMB, *accessLogMaxBackups)
		if err != nil {
			log.Fatalf("access log: %v", err)
		}
		// Deliberately deferred after db.Close() (registered above) so it
		// still exists — LIFO means it runs *before* db.Close() — while
		// runLogWorker drains any queued entries during shutdown.
		defer accessLogWriter.Close()
		db.SetAccessLogFn(accessLogWriter.Push)
	}

	// Bot protection settings come entirely from the DB (managed via Settings page).
	botEnabled, botThreshold, botTTL, _ := db.GetBotSettings()

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
	e.Use(proxy.SecurityMiddleware())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:    true,
		LogStatus: true,
		LogMethod: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			log.Printf("%s %s -> %d", v.Method, v.URI, v.Status)
			return nil
		},
	}))

	h := proxy.NewHandler(registry, engine, wafByService, db, ipbl, geoBl, rl, asnLookup, ch, scorer, adaptivePolicy, cfg.TrustedProxies...)
	// Stops whichever rate-limit backend is active at shutdown — not
	// necessarily rl, since ReloadRateLimit (Settings page) may have hot-
	// swapped it any number of times since startup.
	defer h.StopRateLimit()

	// reloadWAF rebuilds the default engine and every per-service override
	// engine from the current DB state. Called from the WAF Rules page when
	// a global or per-service rule exception is toggled.
	reloadWAF := func() {
		newEngine, newByService, err := buildWAFAll()
		if err != nil {
			log.Printf("waf reload: %v", err)
			return
		}
		h.ReloadWAF(newEngine, newByService)
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
		newBackend := buildRateLimit(db, addr, pwd)
		h.ReloadRateLimit(newBackend)
	}

	uiHandler, err := ui.NewHandler(cfg, db, ipbl, geoBl, registry, broadcaster, staticJS, staticCSS, staticImgs, reloadBot, buildChallenger, reloadRateLimit, reloadWAF, intelWorker.SyncSource, emailReporter.SendNow, webhookPusher.SendTest, emailReporter.SendLoginCode, banner.ReloadConfig, scorer, adaptivePolicy.ReloadConfig, h.Handle)
	if err != nil {
		log.Fatalf("ui init: %v", err)
	}
	uiHandler.Register(e)
	uiHandler.RegisterAPI(e)

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
	e.GET("/_cz/fp.js", func(c echo.Context) error {
		h.ServeFingerprintJS(c.Response().Writer, c.Request())
		return nil
	})
	// Logo + favicon for the challenge page. Served under /_cz/ (not the
	// admin path) because the challenge renders on every proxied domain.
	e.GET("/_cz/logo.svg", func(c echo.Context) error {
		data, err := staticImgs.ReadFile("static/imgs/logo.svg")
		if err != nil {
			return echo.NewHTTPError(http.StatusNotFound)
		}
		c.Response().Header().Set("Cache-Control", "public, max-age=86400")
		return c.Blob(http.StatusOK, "image/svg+xml", data)
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
			newEngine, newByService, err := buildWAFAll()
			if err != nil {
				log.Printf("SIGHUP: WAF reload failed, keeping existing engine: %v", err)
				continue
			}
			h.ReloadWAF(newEngine, newByService)
		}
	}()

	appCount := len(registry.List())

	// TLS only starts when --listen-tls is provided. Certificate config
	// (ACME email, per-service certs) lives entirely in the DB.
	if cfg.ListenAddrTLS != "" {
		if err := startTLS(e, cfg, registry, db, appCount); err != nil && err != http.ErrServerClosed {
			log.Fatalf("tls server: %v", err)
		}
		return
	}
	log.Printf("coraza-waf listening on %s (plain HTTP, waf=%v, apps=%d)",
		cfg.ListenAddr, cfg.WAF.Enabled, appCount)
	shutdownOnSignal(e)
	if err := e.Start(cfg.ListenAddr); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

// startTLS is the single entry point for HTTPS. It reads the ACME contact
// email from the DB, builds an autocert manager if present, then starts HTTP
// on cfg.ListenAddr (ACME challenge handler + HTTPS redirect) and HTTPS on
// cfg.ListenAddrTLS. Per-service custom certs take priority over autocert by
// SNI (see services.Registry.GetCertificateFunc).
func startTLS(e *echo.Echo, cfg *config.Config, registry *services.Registry, db *storage.DB, appCount int) error {
	email, _ := db.GetAcmeEmail()
	primaryDomain, _ := db.GetPrimaryDomain()

	var am *autocert.Manager
	if email != "" {
		if err := os.MkdirAll(cfg.TLS.CacheDir, 0700); err != nil {
			return fmt.Errorf("cannot create cert cache dir %s: %w", cfg.TLS.CacheDir, err)
		}
		// HostPolicy allows services with tls_mode="auto" AND the primary domain
		// (so the admin dashboard's domain gets a Let's Encrypt cert automatically).
		basePolicy := registry.HostPolicy()
		primary := strings.ToLower(primaryDomain)
		am = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				if primary != "" && strings.ToLower(host) == primary {
					return nil
				}
				return basePolicy(ctx, host)
			},
			Cache: autocert.DirCache(cfg.TLS.CacheDir),
			Email: email,
		}
	}

	// Load self-signed fallback cert (used when no per-service/ACME cert matches,
	// e.g. when accessing by IP address or before ACME provisioning completes).
	var fallbackCert *tls.Certificate
	if cfg.TLS.FallbackCertFile != "" && cfg.TLS.FallbackKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.FallbackCertFile, cfg.TLS.FallbackKeyFile)
		if err != nil {
			return fmt.Errorf("load fallback TLS cert: %w", err)
		}
		fallbackCert = &cert
		log.Printf("tls: loaded fallback cert from %s", cfg.TLS.FallbackCertFile)
	}

	// HTTP: ACME HTTP-01 challenge handler (if autocert active) + HTTPS redirect.
	var httpHandler http.Handler = http.HandlerFunc(httpsRedirect)
	if am != nil {
		httpHandler = am.HTTPHandler(httpHandler)
	}
	redirectServer := &http.Server{Addr: cfg.ListenAddr, Handler: httpHandler}
	go func() {
		log.Printf("coraza-waf HTTP (ACME/redirect) on %s", cfg.ListenAddr)
		if err := redirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server: %v", err)
		}
	}()

	s := e.TLSServer
	s.Addr = cfg.ListenAddrTLS
	prevConnState := s.ConnState
	s.ConnState = func(conn net.Conn, state http.ConnState) {
		if prevConnState != nil {
			prevConnState(conn, state)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			ja3pkg.Delete(conn.RemoteAddr().String())
			ja4pkg.Delete(conn.RemoteAddr().String())
			geo.DeleteConn(conn.RemoteAddr().String())
			asn.DeleteConn(conn.RemoteAddr().String())
		}
	}

	// Certificate resolution order:
	//   1. Per-service uploaded cert (by SNI)
	//   2. Per-service / primary-domain ACME cert (by SNI)
	//   3. Self-signed fallback (IP access or ACME not yet provisioned)
	getCertBase := registry.GetCertificateFunc(am)
	primaryLower := strings.ToLower(primaryDomain)
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCertBase(hello)
		if err == nil {
			return cert, nil
		}
		// Primary domain via ACME (not registered as a service).
		if am != nil && primaryLower != "" && strings.ToLower(hello.ServerName) == primaryLower {
			return am.GetCertificate(hello)
		}
		// Fallback: self-signed cert (covers IP-based access).
		if fallbackCert != nil {
			return fallbackCert, nil
		}
		return nil, err
	}

	s.TLSConfig = &tls.Config{
		GetCertificate: getCert,
		// Capture the ClientHello so we can compute JA3 (legacy) and JA4
		// fingerprints for each connection. Both are stored in their package's
		// sync.Map keyed by remoteAddr and retrieved later in the proxy handler
		// when the HTTP request arrives.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			remoteAddr := hello.Conn.RemoteAddr().String()
			if hash := ja3pkg.Compute(hello); hash != "" {
				ja3pkg.Store(remoteAddr, hash)
			}
			ja4pkg.Store(remoteAddr, ja4pkg.Compute(hello))
			return nil, nil
		},
	}

	log.Printf("coraza-waf TLS on %s (waf=%v, apps=%d)", cfg.ListenAddrTLS, cfg.WAF.Enabled, appCount)
	shutdownOnSignal(e, redirectServer)
	return e.StartServer(s)
}

// startCacheReturn binds the loopback listener Varnish fetches cache misses
// from (services.Registry.CacheReturnHandler routes them to the right
// backend). Refuses non-loopback addresses outright: this port proxies
// straight to backends with no WAF pipeline in front, so it must never be
// reachable off-host. Runs for the life of the process — in-flight miss
// fetches are children of requests on the main listener, which graceful
// shutdown already drains.
func startCacheReturn(db *storage.DB, registry *services.Registry) {
	vcfg, err := db.GetVarnishConfig()
	if err != nil {
		log.Printf("cache-return: read varnish config: %v", err)
		return
	}
	host, _, err := net.SplitHostPort(vcfg.ReturnAddr)
	if err != nil {
		log.Printf("cache-return: invalid return address %q: %v", vcfg.ReturnAddr, err)
		return
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Printf("cache-return: refusing to bind non-loopback address %q", vcfg.ReturnAddr)
		return
	}
	srv := &http.Server{Addr: vcfg.ReturnAddr, Handler: registry.CacheReturnHandler()}
	log.Printf("cache-return listener on %s (Varnish miss path)", vcfg.ReturnAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("cache-return listener: %v", err)
	}
}

func shutdownOnSignal(e *echo.Echo, extraServers ...*http.Server) {
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		signal.Stop(sigCh)

		log.Printf("%s: shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, srv := range extraServers {
			if srv == nil {
				continue
			}
			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("http shutdown: %v", err)
				if closeErr := srv.Close(); closeErr != nil {
					log.Printf("http close: %v", closeErr)
				}
			}
		}
		if err := e.Shutdown(ctx); err != nil {
			log.Printf("server shutdown: %v", err)
			if closeErr := e.Close(); closeErr != nil {
				log.Printf("server close: %v", closeErr)
			}
		}
	}()
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// runPruneOnly opens the DB, deletes request logs older than the configured
// retention window plus expired admin sessions, logs the result, and returns
// — it does not start the WAF, proxy, or admin UI. retention <= 0 disables
// request-log pruning (logs kept forever); expired sessions are always swept.
// --vacuum additionally rebuilds the DB file afterwards to hand freed pages
// back to the OS — DELETE alone never shrinks a SQLite file, only marks pages
// reusable, so without an occasional VACUUM the file sits at its high-water
// mark forever. It lives in this one-shot mode rather than the server because
// VACUUM is a single long write transaction: here the live server's writers
// just wait their busy_timeout turn, instead of the rebuild monopolizing the
// serving process's own connection pool.
// Invoked as: coraza-waf-mod prune [--db path] [--retention days] [--vacuum]
func runPruneOnly(args []string) {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	dbPath := fs.String("db", "waf.db", "database path (sqlite) or DSN (mysql/postgres)")
	dbDriver := fs.String("db-driver", "sqlite", "database driver: sqlite, mysql (or mariadb), postgres (or postgresql/cockroachdb/neon)")
	retention := fs.Int("retention", 30, "log retention in days (0 = keep forever)")
	vacuum := fs.Bool("vacuum", false, "rebuild the DB file after pruning to reclaim disk space (sqlite/postgres; no-op on mysql, which has no database-wide VACUUM)")
	fs.Parse(args) //nolint // ExitOnError: never returns an error to check

	db, err := storage.OpenWithDriver(*dbDriver, *dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	if n, err := db.PruneExpiredSessions(); err != nil {
		log.Printf("session prune failed: %v", err)
	} else {
		log.Printf("session prune: deleted %d expired sessions", n)
	}

	if *retention <= 0 {
		log.Printf("log retention: disabled (retention <= 0), nothing to prune")
	} else {
		start := time.Now()
		n, err := db.PruneOldRequests(*retention)
		dur := time.Since(start)
		if err != nil {
			log.Fatalf("log retention: prune failed after %s: %v", dur, err)
		}
		log.Printf("log retention: deleted %d requests older than %d days (took %s)", n, *retention, dur)
	}

	if *vacuum {
		// dbDiskSize stats a SQLite file (plus -wal/-shm sidecars) on the
		// local filesystem — meaningless for a MySQL/Postgres DSN, so the
		// before/after size delta is only reported for the sqlite driver.
		isSQLite := strings.EqualFold(*dbDriver, "") || strings.EqualFold(*dbDriver, "sqlite")
		var before int64
		if isSQLite {
			before = dbDiskSize(*dbPath)
		}
		start := time.Now()
		if err := db.Vacuum(); err != nil {
			log.Fatalf("vacuum: failed after %s: %v", time.Since(start), err)
		}
		switch {
		case isSQLite:
			after := dbDiskSize(*dbPath)
			log.Printf("vacuum: reclaimed %s (%s -> %s, took %s)",
				formatBytes(before-after), formatBytes(before), formatBytes(after), time.Since(start))
		case strings.EqualFold(*dbDriver, "mysql") || strings.EqualFold(*dbDriver, "mariadb"):
			log.Printf("vacuum: no-op on MySQL/MariaDB — there is no database-wide VACUUM; use OPTIMIZE TABLE per table if needed")
		default:
			log.Printf("vacuum: ran VACUUM (took %s) — Postgres/CockroachDB/Neon reclaim space in place, not via file rebuild, so no size delta is reported", time.Since(start))
		}
	}
}

// dbDiskSize sums the on-disk footprint of a SQLite database: the main file
// plus its -wal and -shm sidecars (right after a big prune the WAL can dwarf
// the main file, so counting waf.db alone would misstate what VACUUM
// reclaimed). Missing sidecars contribute zero.
func dbDiskSize(path string) int64 {
	var total int64
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// enableDBEncryption turns on secrets-at-rest encryption from a key file.
// The AES-256 key is SHA-256 of the file's whitespace-trimmed contents rather
// than the raw bytes, so any high-entropy file works regardless of format
// (`openssl rand -hex 32 > db.key`, raw binary, base64) and an editor adding
// a trailing newline doesn't silently derive a different key. The file must
// carry at least 32 bytes so a short passphrase can't quietly stand in for
// real key material — hashing would mask how weak it is.
func enableDBEncryption(db *storage.DB, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 32 {
		return fmt.Errorf("key file %s holds %d bytes; need at least 32 — generate one with: openssl rand -hex 32 > %s", path, len(trimmed), path)
	}
	key := sha256.Sum256(trimmed)
	return db.EnableSecretEncryption(key[:])
}

// formatBytes renders a byte count human-readably for prune log lines.
func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// runSetup seeds admin credentials and optional TLS config into the DB, then
// exits. Idempotent for admin credentials — on upgrades (credentials already
// exist) it skips that step, so re-running the installer never overwrites a
// changed password. Domain and ACME email are always overwritten (safe to
// update during upgrades).
// Invoked as: coraza-waf-mod setup --db path --admin-email email [--domain d] [--acme-email e]
// Password is read from stdin (one line).
func runSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	dbPath := fs.String("db", "waf.db", "database path (sqlite) or DSN (mysql/postgres)")
	dbDriver := fs.String("db-driver", "sqlite", "database driver: sqlite, mysql (or mariadb), postgres (or postgresql/cockroachdb/neon)")
	adminEmail := fs.String("admin-email", "", "admin email address")
	domain := fs.String("domain", "", "primary domain for ACME (Let's Encrypt)")
	acmeEmail := fs.String("acme-email", "", "ACME contact email (defaults to admin email)")
	fs.Parse(args) //nolint // ExitOnError: never returns an error to check

	if *adminEmail == "" {
		log.Fatal("setup: --admin-email is required")
	}

	fmt.Fprint(os.Stderr, "Admin password: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	password := strings.TrimSpace(scanner.Text())
	if password == "" {
		log.Fatal("setup: password cannot be empty")
	}

	db, err := storage.OpenWithDriver(*dbDriver, *dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	if err := db.SeedAdmin(*adminEmail, password); err != nil {
		log.Fatalf("setup: %v", err)
	}
	log.Printf("setup: admin account configured (%s)", *adminEmail)

	if *domain != "" {
		if err := db.SetPrimaryDomain(*domain); err != nil {
			log.Fatalf("setup: store domain: %v", err)
		}
		contactEmail := *acmeEmail
		if contactEmail == "" {
			contactEmail = *adminEmail
		}
		if err := db.SetAcmeEmail(contactEmail); err != nil {
			log.Fatalf("setup: store acme email: %v", err)
		}
		log.Printf("setup: ACME configured for domain %s (contact: %s)", *domain, contactEmail)
	}
}

// runGencert generates a self-signed ECDSA P-256 certificate and writes PEM
// files. The certificate includes the provided hostnames/IPs as SANs so
// browsers don't get a hostname-mismatch error on IP-based access.
// Invoked as: coraza-waf-mod gencert --cert path --key path --hosts ip1,ip2,...
func runGencert(args []string) {
	fs := flag.NewFlagSet("gencert", flag.ExitOnError)
	certFile := fs.String("cert", "cert.pem", "output PEM certificate file")
	keyFile := fs.String("key", "key.pem", "output PEM private key file")
	hosts := fs.String("hosts", "", "comma-separated hostnames and/or IP addresses for SANs")
	days := fs.Int("days", 3650, "certificate validity in days")
	fs.Parse(args) //nolint // ExitOnError: never returns an error to check

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("gencert: generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Coraza WAF Mod"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("gencert: create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("gencert: marshal key: %v", err)
	}

	cf, err := os.OpenFile(*certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("gencert: open cert file: %v", err)
	}
	defer cf.Close()
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}) //nolint:errcheck

	kf, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("gencert: open key file: %v", err)
	}
	defer kf.Close()
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}) //nolint:errcheck

	log.Printf("gencert: wrote %s and %s (valid %d days, hosts: %s)", *certFile, *keyFile, *days, *hosts)
}

// runBuildDSN prints a dialect-correct DSN built from individual fields to
// stdout, then exits — a thin CLI wrapper around storage.BuildDSN so
// deploy/install.sh (and anyone else scripting a MySQL/Postgres connection
// string) doesn't have to hand-roll escaping in shell for a password
// containing ":"/"@"/"/", which would silently corrupt a naive
// fmt.Sprintf-style concatenation. Mirrors the admin Settings page's
// "Database connection" card, which calls the same storage.BuildDSN.
func runBuildDSN(args []string) {
	fs := flag.NewFlagSet("build-dsn", flag.ExitOnError)
	driver := fs.String("driver", "", "database driver: mysql (or mariadb), postgres (or postgresql/cockroachdb/neon)")
	host := fs.String("host", "", "database host: hostname, IP, or Docker service name")
	port := fs.String("port", "", "database port (defaults: mysql 3306, postgres 5432)")
	username := fs.String("username", "", "database username")
	password := fs.String("password", "", "database password")
	dbname := fs.String("dbname", "", "database name")
	sslmode := fs.String("sslmode", "", "mysql: true/false/skip-verify/preferred; postgres: disable/allow/prefer/require/verify-ca/verify-full")
	extra := fs.String("extra", "", "extra DSN parameters as key=value&key2=value2")
	fs.Parse(args) //nolint // ExitOnError: never returns an error to check

	dsn, err := storage.BuildDSN(storage.DBConnFields{
		Driver: *driver, Host: *host, Port: *port, Username: *username,
		Password: *password, DBName: *dbname, SSLMode: *sslmode, Extra: *extra,
	})
	if err != nil {
		log.Fatalf("build-dsn: %v", err)
	}
	fmt.Println(dsn)
}

func httpsRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// buildRateLimit creates the appropriate rate-limit backend from the global
// settings stored in the DB (enabled/rps/burst, managed via the Settings
// page). When global limiting is disabled it returns a no-op Limiter that
// allows everything — for both backend choices, so behavior never depends on
// memory vs Redis. When redisAddr is non-empty, it tries Redis (multi-node);
// on failure or when empty, it falls back to the in-process Limiter with
// SQLite write-back persistence so token-bucket state survives restarts.
func buildRateLimit(db *storage.DB, redisAddr, redisPwd string) ratelimit.Backend {
	enabled, rps, burst, _ := db.GetRateLimitSettings()
	if !enabled {
		log.Printf("rate limit: global limiter disabled (enable from the Settings page)")
		return ratelimit.New(config.RateLimitConfig{})
	}
	if redisAddr != "" {
		rb, err := ratelimit.NewRedisBackend(redisAddr, redisPwd, rps, burst)
		if err != nil {
			log.Printf("rate limit: redis connect failed (%v), falling back to in-memory+SQLite", err)
		} else {
			log.Printf("rate limit: using Redis backend at %s (%.2g rps, burst %d)", redisAddr, rps, burst)
			return rb
		}
	}
	l := ratelimit.New(config.RateLimitConfig{Enabled: true, RequestsPerSecond: rps, Burst: burst})
	if states, err := db.LoadRateLimitState(); err == nil && len(states) > 0 {
		l.RestoreFrom(states)
		log.Printf("rate limit: restored %d buckets from SQLite", len(states))
	}
	l.StartPersistence(db)
	log.Printf("rate limit: in-memory+SQLite backend (%.2g rps, burst %d)", rps, burst)
	return l
}
