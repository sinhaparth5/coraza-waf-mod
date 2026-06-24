// Regenerates static/js/dist/*.min.js from static/js/src/*.js before build.
// `make build` runs this automatically; if running `go build` directly,
// run `go generate ./...` first after editing any source JS file.
//go:generate go run ./tools/minify

package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"coraza-waf-mod/blocklist"
	"coraza-waf-mod/config"
	"coraza-waf-mod/geo"
	"coraza-waf-mod/metrics"
	"coraza-waf-mod/proxy"
	"coraza-waf-mod/services"
	"coraza-waf-mod/storage"
	"coraza-waf-mod/ui"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := waf.New(cfg.WAF)
	if err != nil {
		log.Fatalf("waf init: %v", err)
	}

	db, err := storage.Open(cfg.DB.Path)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()

	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		log.Fatalf("ip blocklist: %v", err)
	}

	geoBl, err := geo.New(cfg.Geo.DBPath, db)
	if err != nil {
		log.Fatalf("geo blocker: %v", err)
	}
	defer geoBl.Close()

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

	broadcaster := ui.NewLogBroadcaster()

	go runLogRetention(db, cfg.DB.LogRetentionDays)

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

	uiHandler, err := ui.NewHandler(cfg, db, ipbl, geoBl, registry, broadcaster, staticJS)
	if err != nil {
		log.Fatalf("ui init: %v", err)
	}
	uiHandler.Register(e)

	h := proxy.NewHandler(registry, engine, db, ipbl, geoBl, broadcaster)
	e.Any("/*", h.Handle)

	appCount := len(registry.List())
	switch cfg.TLS.Mode {
	case "auto":
		startAutoTLS(e, cfg, registry, appCount)
	case "custom":
		startCustomTLS(e, cfg, registry, appCount)
	default:
		log.Printf("coraza-waf listening on %s (plain HTTP, waf=%v, apps=%d)",
			cfg.ListenAddr, cfg.WAF.Enabled, appCount)
		if err := e.Start(cfg.ListenAddr); err != nil {
			log.Fatalf("server: %v", err)
		}
	}
}

// buildAutocertManager sets up Let's Encrypt issuance covering both the
// legacy static tls.auto.domains list and every service whose tls_mode is
// "auto" (added live from the admin UI, not config.yaml). Returns nil if no
// email is configured — ACME requires one for account registration, so
// per-service auto-issue simply can't work without it.
func buildAutocertManager(cfg *config.Config, registry *services.Registry) *autocert.Manager {
	if cfg.TLS.Auto.Email == "" {
		return nil
	}
	if err := os.MkdirAll(cfg.TLS.CacheDir, 0700); err != nil {
		log.Fatalf("cannot create cert cache dir %s: %v", cfg.TLS.CacheDir, err)
	}

	legacyDomains := cfg.TLS.Auto.Domains
	registryPolicy := registry.HostPolicy()
	policy := func(ctx context.Context, host string) error {
		for _, d := range legacyDomains {
			if strings.EqualFold(d, host) {
				return nil
			}
		}
		return registryPolicy(ctx, host)
	}

	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: policy,
		Cache:      autocert.DirCache(cfg.TLS.CacheDir),
		Email:      cfg.TLS.Auto.Email,
	}
}

// startAutoTLS starts HTTPS using Let's Encrypt certificates — for the
// legacy tls.auto.domains list and/or any service configured for per-service
// auto-issue. HTTP on cfg.ListenAddr handles ACME challenges and redirects
// to HTTPS. Per-service uploaded custom certs still take priority by SNI
// even while the global mode is "auto" (see Registry.GetCertificateFunc).
func startAutoTLS(e *echo.Echo, cfg *config.Config, registry *services.Registry, appCount int) {
	tlsCfg := cfg.TLS

	if tlsCfg.Auto.Email == "" {
		log.Fatal("tls.auto.email is required for Let's Encrypt")
	}

	m := buildAutocertManager(cfg, registry)

	// HTTP server: handles ACME HTTP-01 challenge + redirects everything else to HTTPS.
	httpSrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: m.HTTPHandler(http.HandlerFunc(httpsRedirect)),
	}
	go func() {
		log.Printf("HTTP (ACME + redirect) on %s", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http redirect server: %v", err)
		}
	}()

	// HTTPS server: per-service custom cert (by SNI) > autocert > none.
	s := e.TLSServer
	s.Addr = cfg.ListenAddrTLS
	s.TLSConfig = &tls.Config{GetCertificate: registry.GetCertificateFunc(m, nil)}

	log.Printf("coraza-waf listening on %s (Let's Encrypt TLS, domains=%v, waf=%v, apps=%d)",
		cfg.ListenAddrTLS, tlsCfg.Auto.Domains, cfg.WAF.Enabled, appCount)

	if err := e.StartServer(s); err != nil {
		log.Fatalf("tls server: %v", err)
	}
}

// startCustomTLS starts HTTPS using a user-supplied certificate and key as
// the fallback, with per-service uploaded certs (and per-service auto-issue,
// if tls.auto.email is set) taking priority by SNI.
func startCustomTLS(e *echo.Echo, cfg *config.Config, registry *services.Registry, appCount int) {
	tlsCfg := cfg.TLS

	if tlsCfg.Custom.CertFile == "" || tlsCfg.Custom.KeyFile == "" {
		log.Fatal("tls.custom.cert_file and tls.custom.key_file are required for custom TLS mode")
	}
	fallback, err := tls.LoadX509KeyPair(tlsCfg.Custom.CertFile, tlsCfg.Custom.KeyFile)
	if err != nil {
		log.Fatalf("load custom TLS cert: %v", err)
	}

	m := buildAutocertManager(cfg, registry)

	s := e.TLSServer
	s.Addr = cfg.ListenAddrTLS
	s.TLSConfig = &tls.Config{GetCertificate: registry.GetCertificateFunc(m, &fallback)}

	log.Printf("coraza-waf listening on %s (custom TLS, cert=%s, waf=%v, apps=%d)",
		cfg.ListenAddrTLS, tlsCfg.Custom.CertFile, cfg.WAF.Enabled, appCount)

	if err := e.StartServer(s); err != nil {
		log.Fatalf("tls server: %v", err)
	}
}

// runLogRetention prunes request logs older than retentionDays once at
// startup and then once every 24h for the lifetime of the process.
// retentionDays <= 0 disables pruning (logs kept forever).
func runLogRetention(db *storage.DB, retentionDays int) {
	if retentionDays <= 0 {
		log.Printf("log retention: disabled, requests kept forever")
		return
	}

	prune := func() {
		n, err := db.PruneOldRequests(retentionDays)
		if err != nil {
			log.Printf("log retention: prune failed: %v", err)
			return
		}
		if n > 0 {
			log.Printf("log retention: deleted %d requests older than %d days", n, retentionDays)
		}
	}

	prune()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		prune()
	}
}

func httpsRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
