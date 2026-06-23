package main

import (
	"log"
	"os"

	"coraza-waf-mod/config"
	"coraza-waf-mod/proxy"
	"coraza-waf-mod/waf"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

	h := proxy.NewHandler(cfg, engine)
	e.Any("/*", h.Handle)

	log.Printf("coraza-waf listening on %s (waf enabled=%v, apps=%d)",
		cfg.ListenAddr, cfg.WAF.Enabled, len(cfg.Apps))

	if err := e.Start(cfg.ListenAddr); err != nil {
		log.Fatalf("server: %v", err)
	}
}
