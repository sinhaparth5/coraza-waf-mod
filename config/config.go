package config

import (
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	ListenAddr    string      `yaml:"listen_addr"`
	ListenAddrTLS string      `yaml:"listen_addr_tls"`
	Apps          []App       `yaml:"apps"`
	WAF           WAFConfig   `yaml:"waf"`
	TLS           TLSConfig   `yaml:"tls"`
	Geo           GeoConfig   `yaml:"geo"`
	DB            DBConfig    `yaml:"db"`
	Admin         AdminConfig `yaml:"admin"`
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

// TLSConfig controls how the proxy presents TLS to clients.
// mode: "off"    — plain HTTP only (default)
// mode: "auto"   — Let's Encrypt via ACME; certs cached in CacheDir
// mode: "custom" — user-provided cert + key files
type TLSConfig struct {
	Mode     string          `yaml:"mode"`      // "off" | "auto" | "custom"
	CacheDir string          `yaml:"cache_dir"` // where certs are stored (default: "./certs")
	Auto     AutoTLSConfig   `yaml:"auto"`
	Custom   CustomTLSConfig `yaml:"custom"`
}

type AutoTLSConfig struct {
	Domains []string `yaml:"domains"` // domains to issue certs for
	Email   string   `yaml:"email"`   // contact email for Let's Encrypt
}

type CustomTLSConfig struct {
	CertFile string `yaml:"cert_file"` // path to PEM certificate
	KeyFile  string `yaml:"key_file"`  // path to PEM private key
}

type GeoConfig struct {
	DBPath string `yaml:"db_path"` // path to GeoLite2-Country.mmdb; empty = geo blocking disabled
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
	if cfg.ListenAddrTLS == "" {
		cfg.ListenAddrTLS = ":443"
	}
	if cfg.TLS.Mode == "" {
		cfg.TLS.Mode = "off"
	}
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
}
