package config

import (
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	ListenAddr    string          `yaml:"listen_addr"`
	ListenAddrTLS string          `yaml:"listen_addr_tls"`
	Apps          []App           `yaml:"apps"`
	WAF           WAFConfig       `yaml:"waf"`
	TLS           TLSConfig       `yaml:"tls"`
	Geo           GeoConfig       `yaml:"geo"`
	DB            DBConfig        `yaml:"db"`
	Admin         AdminConfig     `yaml:"admin"`
	RateLimit     RateLimitConfig `yaml:"rate_limit"`
}

type App struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`   // virtual-host matching (e.g. "blog.example.com")
	Prefix  string `yaml:"prefix"` // path-prefix matching (e.g. "/api")
	Backend string `yaml:"backend"`
}

type WAFConfig struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"`
}

// TLSConfig holds deployment-level TLS settings. Certificate configuration
// (ACME email, per-service certs) is managed entirely from the admin UI and
// stored in the database — nothing cert-related lives in config.yaml anymore.
type TLSConfig struct {
	CacheDir string `yaml:"cache_dir"` // where Let's Encrypt certs are cached (default: "./certs")
}

type GeoConfig struct {
	DBPath string `yaml:"db_path"` // optional path to GeoLite2-Country.mmdb; empty = bundled DB
}

type DBConfig struct {
	Path string `yaml:"path"`
	// LogRetentionDays: requests older than this are auto-deleted daily.
	// 0 (unset) defaults to 30. Set to -1 to keep logs forever.
	LogRetentionDays int `yaml:"log_retention_days"`
}

type AdminConfig struct {
	Path     string `yaml:"path"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// RateLimitConfig is the in-process per-IP token-bucket limiter applied
// globally ahead of geo/WAF inspection. Disabled by default since the right
// rate depends entirely on the proxied app's traffic shape — an enabled
// default could throttle legitimate traffic on upgrade.
type RateLimitConfig struct {
	Enabled           bool    `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	// ListenAddrTLS has no default — HTTPS only starts when explicitly set.
	// Set it to ":443" (or ":8443" for dev) in config.yaml to enable TLS.
	if cfg.TLS.CacheDir == "" {
		cfg.TLS.CacheDir = "./certs"
	}
	if cfg.DB.Path == "" {
		cfg.DB.Path = "waf.db"
	}
	if cfg.DB.LogRetentionDays == 0 {
		cfg.DB.LogRetentionDays = 30
	}
	if cfg.Admin.Path == "" {
		cfg.Admin.Path = "/admin"
	}
	if cfg.RateLimit.RequestsPerSecond <= 0 {
		cfg.RateLimit.RequestsPerSecond = 10
	}
	if cfg.RateLimit.Burst <= 0 {
		cfg.RateLimit.Burst = 20
	}
}
