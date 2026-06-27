// Regenerates static/js/dist/*.min.js from static/js/src/*.js before build.
// `make build` runs this automatically; if running `go build` directly,
// run `go generate ./...` first after editing any source JS file.
//go:generate go run ./tools/minify

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"coraza-waf-mod/threatintel"
	"coraza-waf-mod/ui"
	"coraza-waf-mod/waf"
	"coraza-waf-mod/webhook"

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
		}
	}

	// CLI flags for bootstrap settings. All runtime knobs (WAF rules, bot
	// protection, Redis, ACME email, per-service overrides) live in the SQLite
	// meta table and are managed from the admin UI — no config file needed.
	fs := flag.NewFlagSet("coraza-waf-mod", flag.ExitOnError)
	listen    := fs.String("listen",     ":8080",   "HTTP listen address")
	listenTLS := fs.String("listen-tls", "",        "HTTPS listen address (empty = HTTP only)")
	dbPath    := fs.String("db",         "waf.db",  "SQLite database path")
	certsDir  := fs.String("certs",      "./certs", "TLS certificate cache directory")
	wafRules  := fs.String("waf-rules",  "",        "extra WAF rules directory (empty = OWASP CRS only)")
	geoDBPath := fs.String("geo-db",     "",        "GeoIP2 database path (empty = bundled)")
	retention := fs.Int("retention",     30,        "request log retention in days (0 = keep forever)")
	tlsCert   := fs.String("tls-cert",   "",        "PEM certificate file for HTTPS fallback (self-signed)")
	tlsKey    := fs.String("tls-key",    "",        "PEM private key file for HTTPS fallback (self-signed)")
	fs.Parse(os.Args[1:])

	cfg := config.Defaults()
	cfg.ListenAddr            = *listen
	cfg.ListenAddrTLS         = *listenTLS
	cfg.DB.Path               = *dbPath
	cfg.TLS.CacheDir          = *certsDir
	cfg.TLS.FallbackCertFile  = *tlsCert
	cfg.TLS.FallbackKeyFile   = *tlsKey
	cfg.WAF.RulesDir          = *wafRules
	cfg.Geo.DBPath            = *geoDBPath
	cfg.DB.LogRetentionDays   = *retention

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
	rl := buildRateLimit(cfg, db, redisAddr, redisPwd)
	defer rl.Stop()

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

	uiHandler, err := ui.NewHandler(cfg, db, ipbl, geoBl, registry, broadcaster, staticJS, staticImgs, reloadBot, buildChallenger, reloadRateLimit, reloadWAF, intelWorker.SyncSource)
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

	// TLS only starts when --listen-tls is provided. Certificate config
	// (ACME email, per-service certs) lives entirely in the DB.
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
// email from the DB, builds an autocert manager if present, then starts HTTP
// on cfg.ListenAddr (ACME challenge handler + HTTPS redirect) and HTTPS on
// cfg.ListenAddrTLS. Per-service custom certs take priority over autocert by
// SNI (see services.Registry.GetCertificateFunc).
func startTLS(e *echo.Echo, cfg *config.Config, registry *services.Registry, db *storage.DB, appCount int) {
	email, _         := db.GetAcmeEmail()
	primaryDomain, _ := db.GetPrimaryDomain()

	var am *autocert.Manager
	if email != "" {
		if err := os.MkdirAll(cfg.TLS.CacheDir, 0700); err != nil {
			log.Fatalf("cannot create cert cache dir %s: %v", cfg.TLS.CacheDir, err)
		}
		// HostPolicy allows services with tls_mode="auto" AND the primary domain
		// (so the admin dashboard's domain gets a Let's Encrypt cert automatically).
		basePolicy := registry.HostPolicy()
		primary    := strings.ToLower(primaryDomain)
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
			log.Fatalf("load fallback TLS cert: %v", err)
		}
		fallbackCert = &cert
		log.Printf("tls: loaded fallback cert from %s", cfg.TLS.FallbackCertFile)
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
// proxy, or admin UI. retention <= 0 disables pruning (logs kept forever).
// Invoked as: coraza-waf-mod prune [--db path] [--retention days]
func runPruneOnly(args []string) {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	dbPath    := fs.String("db",        "waf.db", "SQLite database path")
	retention := fs.Int("retention",    30,        "log retention in days (0 = keep forever)")
	fs.Parse(args)

	if *retention <= 0 {
		log.Printf("log retention: disabled (retention <= 0), nothing to prune")
		return
	}

	db, err := storage.Open(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	start := time.Now()
	n, err := db.PruneOldRequests(*retention)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("log retention: prune failed after %s: %v", dur, err)
	}
	log.Printf("log retention: deleted %d requests older than %d days (took %s)", n, *retention, dur)
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
	dbPath     := fs.String("db",          "waf.db", "SQLite database path")
	adminEmail := fs.String("admin-email", "",       "admin email address")
	domain     := fs.String("domain",      "",       "primary domain for ACME (Let's Encrypt)")
	acmeEmail  := fs.String("acme-email",  "",       "ACME contact email (defaults to admin email)")
	fs.Parse(args)

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

	db, err := storage.Open(*dbPath)
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
	certFile := fs.String("cert",  "cert.pem",  "output PEM certificate file")
	keyFile  := fs.String("key",   "key.pem",   "output PEM private key file")
	hosts    := fs.String("hosts", "",           "comma-separated hostnames and/or IP addresses for SANs")
	days     := fs.Int("days",     3650,         "certificate validity in days")
	fs.Parse(args)

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
