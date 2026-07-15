// Package config defines the runtime configuration for coraza-waf-mod.
// Bootstrap settings (listen addresses, DB path, TLS cache dir) are supplied
// via CLI flags when the binary starts. All other runtime knobs (WAF rules
// toggles, bot protection, Redis config, per-service overrides) are stored in
// the SQLite meta table and managed from the admin UI — no config file needed.
package config

// Config holds the bootstrap settings parsed from CLI flags.
// Fields that map to admin-UI / DB settings (RateLimit, BotProtection, Admin
// credentials) are kept for internal wiring; their values come from defaults
// or the DB, never from a config file.
type Config struct {
	ListenAddr     string
	ListenAddrTLS  string
	TrustedProxies []string // CIDRs allowed to supply X-Forwarded-For / X-Real-IP
	Apps           []App    // kept for one-time migration compat; always empty after first boot
	WAF            WAFConfig
	TLS            TLSConfig
	Geo            GeoConfig
	DB             DBConfig
	Admin          AdminConfig
	RateLimit      RateLimitConfig
	BotProtection  BotProtectionConfig
}

type App struct {
	Name    string
	Host    string
	Prefix  string
	Backend string
}

type WAFConfig struct {
	Enabled  bool
	RulesDir string
}

type TLSConfig struct {
	CacheDir         string // where Let's Encrypt certs are cached
	FallbackCertFile string // PEM cert used when no per-service/ACME cert matches (self-signed)
	FallbackKeyFile  string // matching private key for FallbackCertFile
}

type GeoConfig struct {
	DBPath string // optional path to GeoLite2-Country.mmdb; empty = bundled
}

type DBConfig struct {
	Path             string
	Driver           string // "sqlite" (default), "mysql"/"mariadb", or "postgres"/"postgresql"/"cockroachdb"/"neon" — see storage.resolveDialect
	LogRetentionDays int
}

type AdminConfig struct {
	Path string // URL path prefix for the admin UI (always "/admin")
}

type RateLimitConfig struct {
	Enabled           bool
	RequestsPerSecond float64
	Burst             int
}

type BotProtectionConfig struct {
	Enabled             bool
	AnomalyThreshold    int
	ChallengeTTLSeconds int
}

// Defaults returns a Config populated with sensible defaults. CLI flag parsing
// in main.go overrides individual fields after calling this.
func Defaults() *Config {
	return &Config{
		ListenAddr:     ":8080",
		ListenAddrTLS:  "",
		TrustedProxies: nil,
		WAF:            WAFConfig{Enabled: true},
		TLS:            TLSConfig{CacheDir: "./certs"},
		DB:             DBConfig{Path: "waf.db", Driver: "sqlite", LogRetentionDays: 30},
		Admin:          AdminConfig{Path: "/admin"},
		RateLimit:      RateLimitConfig{RequestsPerSecond: 10, Burst: 20},
		BotProtection:  BotProtectionConfig{AnomalyThreshold: 8, ChallengeTTLSeconds: 3600},
	}
}
