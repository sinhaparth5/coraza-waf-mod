package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"

	"coraza-waf-mod/config"
	"coraza-waf-mod/proxy"
	"coraza-waf-mod/storage"
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

	h := proxy.NewHandler(cfg, engine, db)
	e.Any("/*", h.Handle)

	switch cfg.TLS.Mode {
	case "auto":
		startAutoTLS(e, cfg)
	case "custom":
		startCustomTLS(e, cfg)
	default:
		log.Printf("coraza-waf listening on %s (plain HTTP, waf=%v, apps=%d)",
			cfg.ListenAddr, cfg.WAF.Enabled, len(cfg.Apps))
		if err := e.Start(cfg.ListenAddr); err != nil {
			log.Fatalf("server: %v", err)
		}
	}
}

// startAutoTLS starts HTTPS using Let's Encrypt certificates.
// HTTP on cfg.ListenAddr handles ACME challenges and redirects to HTTPS.
func startAutoTLS(e *echo.Echo, cfg *config.Config) {
	tlsCfg := cfg.TLS

	if len(tlsCfg.Auto.Domains) == 0 {
		log.Fatal("tls.auto.domains must list at least one domain for Let's Encrypt")
	}
	if tlsCfg.Auto.Email == "" {
		log.Fatal("tls.auto.email is required for Let's Encrypt")
	}

	if err := os.MkdirAll(tlsCfg.CacheDir, 0700); err != nil {
		log.Fatalf("cannot create cert cache dir %s: %v", tlsCfg.CacheDir, err)
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(tlsCfg.Auto.Domains...),
		Cache:      autocert.DirCache(tlsCfg.CacheDir),
		Email:      tlsCfg.Auto.Email,
	}

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

	// HTTPS server with autocert.
	s := e.TLSServer
	s.Addr = cfg.ListenAddrTLS
	s.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

	log.Printf("coraza-waf listening on %s (Let's Encrypt TLS, domains=%v, waf=%v, apps=%d)",
		cfg.ListenAddrTLS, tlsCfg.Auto.Domains, cfg.WAF.Enabled, len(cfg.Apps))

	if err := e.StartServer(s); err != nil {
		log.Fatalf("tls server: %v", err)
	}
}

// startCustomTLS starts HTTPS using a user-supplied certificate and key.
func startCustomTLS(e *echo.Echo, cfg *config.Config) {
	tlsCfg := cfg.TLS

	if tlsCfg.Custom.CertFile == "" || tlsCfg.Custom.KeyFile == "" {
		log.Fatal("tls.custom.cert_file and tls.custom.key_file are required for custom TLS mode")
	}

	log.Printf("coraza-waf listening on %s (custom TLS, cert=%s, waf=%v, apps=%d)",
		cfg.ListenAddrTLS, tlsCfg.Custom.CertFile, cfg.WAF.Enabled, len(cfg.Apps))

	if err := e.StartTLS(cfg.ListenAddrTLS, tlsCfg.Custom.CertFile, tlsCfg.Custom.KeyFile); err != nil {
		log.Fatalf("tls server: %v", err)
	}
}

func httpsRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
