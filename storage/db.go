package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/ratelimit"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// logQueueSize bounds how many request-log entries can be buffered waiting
// to be written. At sustained traffic far beyond what this WAF is sized for,
// entries are dropped (and logged) rather than blocking the request path —
// see QueueRequest.
const logQueueSize = 10000

// slowWriteThreshold gates the diagnostic log in runLogWorker — a single
// InsertRequest taking this long usually means something else (a long-held
// writer lock, e.g. a prune batch, or slow disk I/O) is making every queued
// write wait its turn.
const slowWriteThreshold = 500 * time.Millisecond

type DB struct {
	conn        *sql.DB
	logQueue    chan RequestLog
	logDone     chan struct{}
	broadcastFn func(RequestLog)
	webhookFn   func(RequestLog)
	autobanFn   func(RequestLog)
}

// SetAutobanFn registers a callback invoked (from the log worker goroutine)
// after each successful DB insert. Used to feed blocked events to the
// automatic IP banner without coupling storage to the autoban package.
// The callback must be fast — it runs on the single log worker goroutine.
func (db *DB) SetAutobanFn(fn func(RequestLog)) {
	db.autobanFn = fn
}

// SetWebhookFn registers a callback invoked (from the log worker goroutine)
// after each successful DB insert. Used to push security events to the webhook
// pusher without coupling storage to the webhook package.
func (db *DB) SetWebhookFn(fn func(RequestLog)) {
	db.webhookFn = fn
}

// SetBroadcastFn registers a callback invoked after each successful DB insert,
// with entry.ID set to the real row ID. Called from main.go to wire the UI
// broadcaster without importing ui from storage.
func (db *DB) SetBroadcastFn(fn func(RequestLog)) {
	db.broadcastFn = fn
}

// RequestLog is one row in the requests table.
type RequestLog struct {
	ID          int // populated after DB insert; 0 until then
	Timestamp   time.Time
	AppName     string
	RealIP      string
	ProxyIP     string // raw TCP RemoteAddr (CDN/LB edge IP when behind Cloudflare)
	Country     string // ISO 3166-1 alpha-2, e.g. "US", "CN"
	Method      string
	Host        string
	Path        string
	Query       string // raw query string (without leading "?")
	Status      int
	Blocked     bool
	RuleID      int
	Action      string
	UserAgent   string
	Duration    int64  // milliseconds
	HeadersJSON string // JSON-encoded map[string]string of request headers
	RequestID   string // random hex per-request correlation ID
	Proto       string // HTTP/1.1, HTTP/2.0, etc.
	TLSVersion  string // "TLS 1.3", "TLS 1.2", "" for plaintext
	TLSCipher   string // e.g. "TLS_AES_128_GCM_SHA256"
	TLSSNI      string // SNI hostname from TLS ClientHello
	ASN         uint   // autonomous system number
	Org         string // ISP / organization name
	JA3Hash     string // JA3 TLS fingerprint MD5 hex (legacy); empty for plain HTTP
	JA4         string // JA4 TLS fingerprint (a_b_c format); empty for plain HTTP
	VisitorID   string // FingerprintJS browser fingerprint from the bot-challenge bypass cookie; "" when unchallenged
	BotScore    int    // anomaly score from bot signal analysis (0 = clean)
}

func Open(path string) (*DB, error) {
	// PRAGMAs are passed via the DSN (modernc.org/sqlite applies "_pragma"
	// query params to every new physical connection as it's opened — see
	// applyQueryParams in its driver), not via a one-off Exec after Open:
	// database/sql pools multiple connections, and an Exec only configures
	// whichever single connection happens to run it, silently leaving every
	// other pooled connection with no busy_timeout at all. journal_mode=WAL
	// lets readers proceed without blocking on a writer; busy_timeout makes
	// concurrent writers wait their turn at the SQLite engine level instead
	// of failing instantly with SQLITE_BUSY.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite still only allows one writer at a time regardless of pool size,
	// but WAL mode lets multiple readers proceed concurrently with that one
	// writer — so a small pool (rather than 1) lets reads (dashboard, logs
	// page) avoid queuing behind writes (request logging).
	conn.SetMaxOpenConns(8)

	db := &DB{
		conn:     conn,
		logQueue: make(chan RequestLog, logQueueSize),
		logDone:  make(chan struct{}),
	}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	go db.runLogWorker()
	return db, nil
}

// runLogWorker drains logQueue on a single dedicated goroutine, so a slow or
// momentarily-contended write never blocks the request path that produced
// it (see QueueRequest). Exits once logQueue is closed and drained.
func (db *DB) runLogWorker() {
	defer close(db.logDone)
	for entry := range db.logQueue {
		writeStart := time.Now()
		id, err := db.InsertRequest(entry)
		dur := time.Since(writeStart)
		if err != nil {
			log.Printf("storage: async request log write failed after %s: %v", dur, err)
		} else {
			if dur >= slowWriteThreshold {
				log.Printf("storage: slow request log write, took %s (queue depth now %d)", dur, db.QueueDepth())
			}
			entry.ID = int(id)
			if db.broadcastFn != nil {
				db.broadcastFn(entry)
			}
			if db.webhookFn != nil {
				db.webhookFn(entry)
			}
			if db.autobanFn != nil {
				db.autobanFn(entry)
			}
		}
	}
}

// QueueRequest enqueues a request log entry to be written by the background
// worker instead of blocking the caller on the DB write. If the queue is
// completely full (sustained traffic far beyond what this WAF is sized for),
// the entry is dropped rather than blocking the request that triggered it.
func (db *DB) QueueRequest(entry RequestLog) {
	select {
	case db.logQueue <- entry:
	default:
		log.Printf("storage: request log queue full (>%d), dropping entry", logQueueSize)
	}
}

// QueueDepth returns the number of entries currently buffered in logQueue,
// waiting to be written by the background worker. Used by the /metrics
// endpoint to surface logging backpressure.
func (db *DB) QueueDepth() int {
	return len(db.logQueue)
}

func (db *DB) Close() error {
	close(db.logQueue)
	<-db.logDone
	return db.conn.Close()
}

func (db *DB) migrate() error {
	// Idempotent column migration for existing databases.
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN country TEXT NOT NULL DEFAULT ''`)             //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN proxy_ip TEXT NOT NULL DEFAULT ''`)            //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN headers_json TEXT NOT NULL DEFAULT ''`)        //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN request_id TEXT NOT NULL DEFAULT ''`)          //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN proto TEXT NOT NULL DEFAULT ''`)               //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN tls_version TEXT NOT NULL DEFAULT ''`)         //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN tls_cipher TEXT NOT NULL DEFAULT ''`)          //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN tls_sni TEXT NOT NULL DEFAULT ''`)             //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN asn_num INTEGER NOT NULL DEFAULT 0`)           //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN org TEXT NOT NULL DEFAULT ''`)                 //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN query TEXT NOT NULL DEFAULT ''`)               //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN ja3_hash TEXT NOT NULL DEFAULT ''`)            //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN ja4 TEXT NOT NULL DEFAULT ''`)                 //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN visitor_id TEXT NOT NULL DEFAULT ''`)          //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN bot_score INTEGER NOT NULL DEFAULT 0`)         //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_mode TEXT NOT NULL DEFAULT 'none'`)        //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_cert_path TEXT NOT NULL DEFAULT ''`)       //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_key_path TEXT NOT NULL DEFAULT ''`)        //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_expires_at TEXT NOT NULL DEFAULT ''`)      //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN rate_limit_rps REAL NOT NULL DEFAULT 0`)       //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN rate_limit_burst INTEGER NOT NULL DEFAULT 0`)  //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN bot_mode TEXT NOT NULL DEFAULT 'inherit'`)     //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN cert_id INTEGER NOT NULL DEFAULT 0`)           //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN cache_enabled INTEGER NOT NULL DEFAULT 0`)     //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN cache_by_session INTEGER NOT NULL DEFAULT 0`)  //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN session_cookie_name TEXT NOT NULL DEFAULT ''`) //nolint
	db.conn.Exec(`ALTER TABLE ip_rules ADD COLUMN note TEXT NOT NULL DEFAULT ''`)                //nolint

	_, err := db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS requests (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		ts           DATETIME NOT NULL,
		app_name     TEXT NOT NULL,
		real_ip      TEXT NOT NULL,
		proxy_ip     TEXT NOT NULL DEFAULT '',
		country      TEXT NOT NULL DEFAULT '',
		method       TEXT NOT NULL,
		host         TEXT NOT NULL,
		path         TEXT NOT NULL,
		query        TEXT NOT NULL DEFAULT '',
		status       INTEGER NOT NULL,
		blocked      INTEGER NOT NULL DEFAULT 0,
		rule_id      INTEGER NOT NULL DEFAULT 0,
		action       TEXT NOT NULL DEFAULT '',
		user_agent   TEXT NOT NULL DEFAULT '',
		duration_ms  INTEGER NOT NULL DEFAULT 0,
		headers_json TEXT NOT NULL DEFAULT '',
		request_id   TEXT NOT NULL DEFAULT '',
		proto        TEXT NOT NULL DEFAULT '',
		tls_version  TEXT NOT NULL DEFAULT '',
		tls_cipher   TEXT NOT NULL DEFAULT '',
		tls_sni      TEXT NOT NULL DEFAULT '',
		asn_num      INTEGER NOT NULL DEFAULT 0,
		org          TEXT NOT NULL DEFAULT '',
		ja3_hash     TEXT NOT NULL DEFAULT '',
		ja4          TEXT NOT NULL DEFAULT '',
		visitor_id   TEXT NOT NULL DEFAULT '',
		bot_score    INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_requests_ts         ON requests(ts);
	CREATE INDEX IF NOT EXISTS idx_requests_ip         ON requests(real_ip);
	CREATE INDEX IF NOT EXISTS idx_requests_blocked    ON requests(blocked);
	CREATE INDEX IF NOT EXISTS idx_requests_app        ON requests(app_name);
	CREATE INDEX IF NOT EXISTS idx_requests_blocked_ts ON requests(blocked, ts);

	CREATE TABLE IF NOT EXISTS ip_rules (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		app_name   TEXT NOT NULL DEFAULT '',
		ip         TEXT NOT NULL,
		rule_type  TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
		note       TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(app_name, ip)
	);

	CREATE TABLE IF NOT EXISTS geo_rules (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		app_name     TEXT NOT NULL DEFAULT '',
		country_code TEXT NOT NULL,
		rule_type    TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
		created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(app_name, country_code)
	);

	CREATE TABLE IF NOT EXISTS meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS services (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		name             TEXT NOT NULL UNIQUE,
		host             TEXT NOT NULL DEFAULT '',
		prefix           TEXT NOT NULL DEFAULT '',
		backend          TEXT NOT NULL,
		created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		tls_mode         TEXT NOT NULL DEFAULT 'none',
		tls_cert_path    TEXT NOT NULL DEFAULT '',
		tls_key_path     TEXT NOT NULL DEFAULT '',
		tls_expires_at   TEXT NOT NULL DEFAULT '',
		rate_limit_rps   REAL NOT NULL DEFAULT 0,
		rate_limit_burst INTEGER NOT NULL DEFAULT 0,
		bot_mode         TEXT NOT NULL DEFAULT 'inherit',
		cert_id          INTEGER NOT NULL DEFAULT 0,
		cache_enabled    INTEGER NOT NULL DEFAULT 0,
		cache_by_session INTEGER NOT NULL DEFAULT 0,
		session_cookie_name TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id          INTEGER  PRIMARY KEY AUTOINCREMENT,
		name        TEXT     NOT NULL UNIQUE,
		domains     TEXT     NOT NULL DEFAULT '',
		expires_at  TEXT     NOT NULL DEFAULT '',
		cert_path   TEXT     NOT NULL DEFAULT '',
		key_path    TEXT     NOT NULL DEFAULT '',
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token      TEXT PRIMARY KEY,
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS rate_state (
		ip          TEXT PRIMARY KEY,
		tokens      REAL NOT NULL,
		last_refill TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS waf_disabled_rules (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id    INTEGER NOT NULL UNIQUE,
		reason     TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS threat_intel_sources (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		label          TEXT NOT NULL,
		url            TEXT NOT NULL UNIQUE,
		interval_hours INTEGER NOT NULL DEFAULT 24,
		enabled        INTEGER NOT NULL DEFAULT 1,
		last_synced_at TEXT NOT NULL DEFAULT '',
		last_error     TEXT NOT NULL DEFAULT '',
		ip_count       INTEGER NOT NULL DEFAULT 0,
		created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS threat_intel_ips (
		source_id INTEGER NOT NULL,
		ip        TEXT NOT NULL,
		PRIMARY KEY (source_id, ip)
	);

	CREATE TABLE IF NOT EXISTS webhook_config (
		id      INTEGER PRIMARY KEY CHECK (id = 1),
		url     TEXT    NOT NULL DEFAULT '',
		secret  TEXT    NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 0,
		events  TEXT    NOT NULL DEFAULT 'blocked,challenged'
	);
	INSERT OR IGNORE INTO webhook_config (id) VALUES (1);
	`)
	if err != nil {
		return err
	}

	// Seed the notifications baseline at startup (not lazily on first access)
	// so a block that happens before any admin page has ever been loaded
	// still counts as "unread" instead of racing the lazy-init.
	_, err = db.conn.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		metaKeyNotificationsSeenAt, time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

// ── IP rules ─────────────────────────────────────────────────────────────────

type IPRule struct {
	ID        int
	AppName   string // "" = global
	IP        string
	RuleType  string // "block" | "allow"
	Note      string // "" for manual rules; ban reason for auto-banned IPs
	CreatedAt time.Time
}

// Auto reports whether this rule was created by the automatic IP banner
// (rather than entered by an admin). Used by the IP Rules page template.
func (r IPRule) Auto() bool { return strings.HasPrefix(r.Note, "Auto-banned") }

func (db *DB) AddIPRule(appName, ip, ruleType string) error {
	return db.AddIPRuleWithNote(appName, ip, ruleType, "")
}

// AddIPRuleWithNote upserts an IP rule carrying a note (shown on the IP Rules
// page). The autoban package uses the note to record why an IP was banned.
func (db *DB) AddIPRuleWithNote(appName, ip, ruleType, note string) error {
	_, err := db.conn.Exec(
		`INSERT INTO ip_rules (app_name, ip, rule_type, note) VALUES (?, ?, ?, ?)
		 ON CONFLICT(app_name, ip) DO UPDATE SET rule_type = excluded.rule_type, note = excluded.note`,
		appName, ip, ruleType, note,
	)
	return err
}

// GetIPRuleType returns the rule type ("block" or "allow") for an exact
// app+IP pair, or "" when no rule exists. The autoban package checks this
// before banning so an admin allow rule (or an existing ban) is never
// overwritten.
func (db *DB) GetIPRuleType(appName, ip string) (string, error) {
	var rt string
	err := db.conn.QueryRow(
		`SELECT rule_type FROM ip_rules WHERE app_name = ? AND ip = ?`, appName, ip,
	).Scan(&rt)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return rt, err
}

func (db *DB) RemoveIPRule(id int) error {
	_, err := db.conn.Exec(`DELETE FROM ip_rules WHERE id = ?`, id)
	return err
}

func (db *DB) ListIPRules() ([]IPRule, error) {
	rows, err := db.conn.Query(
		`SELECT id, app_name, ip, rule_type, note, created_at FROM ip_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.AppName, &r.IP, &r.RuleType, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ── Autoban config ───────────────────────────────────────────────────────────

// AutobanConfig controls the automatic IP banner (autoban package). Stored in
// the meta table and managed from the IP Rules page.
type AutobanConfig struct {
	Enabled       bool
	Threshold     int // points within the window that trigger a permanent ban
	WindowMinutes int // sliding window size
}

// DefaultAutobanConfig is used when nothing is stored yet: enabled, ban at 10
// points in 10 minutes (≈2 critical WAF hits, 4 generic WAF hits, or 10
// rate-limited requests — see autoban's scoring).
func DefaultAutobanConfig() AutobanConfig {
	return AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 10}
}

func (db *DB) GetAutobanConfig() (AutobanConfig, error) {
	cfg := DefaultAutobanConfig()
	if v, err := db.getMeta("autoban_enabled"); err != nil {
		return cfg, err
	} else if v != "" {
		cfg.Enabled = v == "1"
	}
	if v, _ := db.getMeta("autoban_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Threshold = n
		}
	}
	if v, _ := db.getMeta("autoban_window_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.WindowMinutes = n
		}
	}
	return cfg, nil
}

func (db *DB) SetAutobanConfig(cfg AutobanConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("autoban_enabled", enabled); err != nil {
		return err
	}
	if err := db.setMeta("autoban_threshold", strconv.Itoa(cfg.Threshold)); err != nil {
		return err
	}
	return db.setMeta("autoban_window_min", strconv.Itoa(cfg.WindowMinutes))
}

// ── Varnish cache config ─────────────────────────────────────────────────────

// VarnishConfig controls the optional Varnish accelerator sitting between the
// WAF and cache-enabled backends. Stored in the meta table and managed from
// the Settings page. Traffic makes a loopback round trip:
//
//	client → WAF (:80/:443) → varnishd (Addr) → WAF cache-return (ReturnAddr) → backend
//
// Cache misses come back to the WAF's cache-return listener, which routes to
// the real backend from the services table — so the Varnish VCL needs exactly
// one static backend (ReturnAddr) and never changes when services do. Both
// addresses must stay loopback-only so nothing reaches the cache, or the
// return listener's direct-to-backend path, without passing the WAF first.
type VarnishConfig struct {
	Enabled    bool
	Addr       string // host:port of varnishd, e.g. "127.0.0.1:6081"
	ReturnAddr string // host:port the WAF's cache-return listener binds, e.g. "127.0.0.1:6082"
}

// DefaultVarnishAddr and DefaultVarnishReturnAddr match the deploy/varnish
// systemd configuration and the VCL's single backend.
const (
	DefaultVarnishAddr       = "127.0.0.1:6081"
	DefaultVarnishReturnAddr = "127.0.0.1:6082"
)

func (db *DB) GetVarnishConfig() (VarnishConfig, error) {
	cfg := VarnishConfig{Addr: DefaultVarnishAddr, ReturnAddr: DefaultVarnishReturnAddr}
	v, err := db.getMeta("varnish_enabled")
	if err != nil {
		return cfg, err
	}
	cfg.Enabled = v == "1"
	if addr, _ := db.getMeta("varnish_addr"); addr != "" {
		cfg.Addr = addr
	}
	if addr, _ := db.getMeta("varnish_return_addr"); addr != "" {
		cfg.ReturnAddr = addr
	}
	return cfg, nil
}

func (db *DB) SetVarnishConfig(cfg VarnishConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("varnish_enabled", enabled); err != nil {
		return err
	}
	if err := db.setMeta("varnish_addr", cfg.Addr); err != nil {
		return err
	}
	if cfg.ReturnAddr == "" {
		cfg.ReturnAddr = DefaultVarnishReturnAddr
	}
	return db.setMeta("varnish_return_addr", cfg.ReturnAddr)
}

// ── Geo rules ─────────────────────────────────────────────────────────────────

type GeoRule struct {
	ID          int
	AppName     string // "" = global
	CountryCode string // ISO 3166-1 alpha-2 (e.g. "CN", "RU")
	RuleType    string // "block" | "allow"
	CreatedAt   time.Time
}

func (db *DB) AddGeoRule(appName, countryCode, ruleType string) error {
	_, err := db.conn.Exec(
		`INSERT INTO geo_rules (app_name, country_code, rule_type) VALUES (?, ?, ?)
		 ON CONFLICT(app_name, country_code) DO UPDATE SET rule_type = excluded.rule_type`,
		appName, countryCode, ruleType,
	)
	return err
}

func (db *DB) RemoveGeoRule(id int) error {
	_, err := db.conn.Exec(`DELETE FROM geo_rules WHERE id = ?`, id)
	return err
}

func (db *DB) ListGeoRules() ([]GeoRule, error) {
	rows, err := db.conn.Query(
		`SELECT id, app_name, country_code, rule_type, created_at FROM geo_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []GeoRule
	for rows.Next() {
		var r GeoRule
		if err := rows.Scan(&r.ID, &r.AppName, &r.CountryCode, &r.RuleType, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ── Services ─────────────────────────────────────────────────────────────────

// Service is one backend app the proxy can route to, matched by Host header
// or path Prefix (at least one of the two must be set).
//
// TLS fields only apply to Host-matched services — TLS termination happens
// via SNI at the handshake, which needs a domain name, not a path prefix.
// TLSMode is "none" (plain HTTP only), "custom" (admin-uploaded cert/key,
// paths point at files under certs/services/<name>/), or "auto" (issued
// on-demand via Let's Encrypt/autocert). TLSExpiresAt is RFC3339, "" if
// unknown or not yet issued.
type Service struct {
	ID                int
	Name              string
	Host              string
	Prefix            string
	Backend           string
	CreatedAt         time.Time
	TLSMode           string
	TLSCertPath       string
	TLSKeyPath        string
	TLSExpiresAt      string
	RateLimitRPS      float64
	RateLimitBurst    int
	BotMode           string // "inherit" | "always" | "off"
	CertID            int64  // >0 when TLS cert comes from the shared cert pool
	CacheEnabled      bool   // route clean traffic through the local Varnish cache
	CacheBySession    bool   // partition cached objects by SessionCookieName's value instead of refusing to cache any cookie-bearing request
	SessionCookieName string // name of this service's session cookie; required for CacheBySession to take effect
}

func (db *DB) AddService(name, host, prefix, backend string, rps float64, burst int) error {
	_, err := db.conn.Exec(
		`INSERT INTO services (name, host, prefix, backend, rate_limit_rps, rate_limit_burst) VALUES (?, ?, ?, ?, ?, ?)`,
		name, host, prefix, backend, rps, burst,
	)
	return err
}

func (db *DB) UpdateService(id int, name, host, prefix, backend string) error {
	_, err := db.conn.Exec(
		`UPDATE services SET name = ?, host = ?, prefix = ?, backend = ? WHERE id = ?`,
		name, host, prefix, backend, id,
	)
	return err
}

func (db *DB) RemoveService(id int) error {
	_, err := db.conn.Exec(`DELETE FROM services WHERE id = ?`, id)
	return err
}

// SetServiceTLS records a service's TLS configuration. For mode "custom",
// certPath/keyPath point at files on disk (see services.SaveCustomCert);
// for mode "auto" they're left empty since autocert manages its own cache.
func (db *DB) SetServiceTLS(id int, mode, certPath, keyPath, expiresAt string) error {
	_, err := db.conn.Exec(
		`UPDATE services SET tls_mode = ?, tls_cert_path = ?, tls_key_path = ?, tls_expires_at = ? WHERE id = ?`,
		mode, certPath, keyPath, expiresAt, id,
	)
	return err
}

// ClearServiceTLS reverts a service to plain HTTP (no TLS), including clearing
// any reference to a pool cert.
func (db *DB) ClearServiceTLS(id int) error {
	_, err := db.conn.Exec(
		`UPDATE services SET tls_mode = 'none', tls_cert_path = '', tls_key_path = '', tls_expires_at = '', cert_id = 0 WHERE id = ?`,
		id,
	)
	return err
}

// SetServiceCertID links a service to a cert-pool entry. Sets tls_mode to
// "custom" and clears the old per-service cert paths since the cert now comes
// from the pool. Set certID to 0 to remove the pool association (use
// ClearServiceTLS to fully revert to plain HTTP).
func (db *DB) SetServiceCertID(serviceID int, certID int64) error {
	_, err := db.conn.Exec(
		`UPDATE services SET cert_id = ?, tls_mode = 'custom', tls_cert_path = '', tls_key_path = '', tls_expires_at = '' WHERE id = ?`,
		certID, serviceID,
	)
	return err
}

// SetServiceRateLimit configures a per-service per-IP rate limit.
// rps=0 disables per-service limiting for this service (falls through to the
// global limiter only).
func (db *DB) SetServiceRateLimit(id int, rps float64, burst int) error {
	_, err := db.conn.Exec(
		`UPDATE services SET rate_limit_rps = ?, rate_limit_burst = ? WHERE id = ?`,
		rps, burst, id,
	)
	return err
}

// SetServiceBotMode sets the per-service bot protection override.
// mode must be one of "inherit", "always", or "off".
func (db *DB) SetServiceBotMode(id int, mode string) error {
	_, err := db.conn.Exec(`UPDATE services SET bot_mode = ? WHERE id = ?`, mode, id)
	return err
}

// SetServiceCache toggles routing this service's clean traffic through the
// local Varnish cache. Only takes effect while the global Varnish integration
// (VarnishConfig.Enabled) is on — the flag is kept independent so per-service
// choices survive the cache layer being switched off and on.
func (db *DB) SetServiceCache(id int, enabled bool) error {
	_, err := db.conn.Exec(`UPDATE services SET cache_enabled = ? WHERE id = ?`, enabled, id)
	return err
}

// SetServiceCacheSession configures opt-in session-aware caching for a
// service: when enabled, cached objects are partitioned per session-cookie
// value (see services.Registry's Director and deploy/varnish/default.vcl)
// instead of Varnish refusing to cache any request that carries a cookie.
// cookieName is the name of this service's session cookie; enabled has no
// effect until it's set to a non-empty value.
func (db *DB) SetServiceCacheSession(id int, enabled bool, cookieName string) error {
	_, err := db.conn.Exec(`UPDATE services SET cache_by_session = ?, session_cookie_name = ? WHERE id = ?`, enabled, cookieName, id)
	return err
}

// ── Certificate Pool ──────────────────────────────────────────────────────────

// CertRecord is a row in the certificates table. Cert+key files live on disk
// under certs/pool/<id>/; only the paths are stored here.
type CertRecord struct {
	ID        int64
	Name      string
	Domains   string // comma-separated list of covered hostnames, e.g. "example.com, *.example.com"
	ExpiresAt string // RFC3339, or "" if unknown
	CertPath  string
	KeyPath   string
	CreatedAt string
}

// AddCertificate inserts a new certificate pool entry. Cert+key paths may be
// empty initially and updated with UpdateCertificatePaths once files are saved.
func (db *DB) AddCertificate(name, domains, expiresAt, certPath, keyPath string) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO certificates (name, domains, expires_at, cert_path, key_path) VALUES (?, ?, ?, ?, ?)`,
		name, domains, expiresAt, certPath, keyPath,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateCertificatePaths stores the on-disk file paths after the files have
// been written (called immediately after AddCertificate + SavePoolCert).
func (db *DB) UpdateCertificatePaths(id int64, certPath, keyPath string) error {
	_, err := db.conn.Exec(
		`UPDATE certificates SET cert_path = ?, key_path = ? WHERE id = ?`,
		certPath, keyPath, id,
	)
	return err
}

func (db *DB) ListCertificates() ([]CertRecord, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var c CertRecord
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.ExpiresAt, &c.CertPath, &c.KeyPath, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) GetCertificate(id int64) (CertRecord, error) {
	var c CertRecord
	err := db.conn.QueryRow(
		`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates WHERE id = ?`, id,
	).Scan(&c.ID, &c.Name, &c.Domains, &c.ExpiresAt, &c.CertPath, &c.KeyPath, &c.CreatedAt)
	return c, err
}

// DeleteCertificate removes a cert-pool entry. Services that referenced it
// via cert_id are reset to tls_mode='none' so they don't silently lose TLS.
func (db *DB) DeleteCertificate(id int64) error {
	if _, err := db.conn.Exec(
		`UPDATE services SET tls_mode = 'none', cert_id = 0, tls_cert_path = '', tls_key_path = '', tls_expires_at = '' WHERE cert_id = ?`,
		id,
	); err != nil {
		return err
	}
	_, err := db.conn.Exec(`DELETE FROM certificates WHERE id = ?`, id)
	return err
}

// GetBotSettings reads global bot protection settings from the meta table.
// Returns defaults (disabled, threshold=8, ttl=3600) if not yet configured.
func (db *DB) GetBotSettings() (enabled bool, threshold, ttl int, err error) {
	threshold, ttl = 8, 3600
	if v, e := db.getMeta("bot_enabled"); e == nil {
		enabled = v == "1"
	}
	if v, e := db.getMeta("bot_threshold"); e == nil && v != "" {
		if n, e2 := strconv.Atoi(v); e2 == nil && n > 0 {
			threshold = n
		}
	}
	if v, e := db.getMeta("bot_ttl"); e == nil && v != "" {
		if n, e2 := strconv.Atoi(v); e2 == nil && n > 0 {
			ttl = n
		}
	}
	return
}

// SetBotSettings persists global bot protection settings to the meta table.
func (db *DB) SetBotSettings(enabled bool, threshold, ttl int) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := db.setMeta("bot_enabled", v); err != nil {
		return err
	}
	if err := db.setMeta("bot_threshold", strconv.Itoa(threshold)); err != nil {
		return err
	}
	return db.setMeta("bot_ttl", strconv.Itoa(ttl))
}

func (db *DB) ListServices() ([]Service, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at, rate_limit_rps, rate_limit_burst, bot_mode, cert_id, cache_enabled, cache_by_session, session_cookie_name FROM services ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		var s Service
		if err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt, &s.RateLimitRPS, &s.RateLimitBurst, &s.BotMode, &s.CertID, &s.CacheEnabled, &s.CacheBySession, &s.SessionCookieName); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetService fetches a single service by ID.
func (db *DB) GetService(id int) (Service, error) {
	var s Service
	err := db.conn.QueryRow(
		`SELECT id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at, rate_limit_rps, rate_limit_burst, bot_mode, cert_id, cache_enabled, cache_by_session, session_cookie_name FROM services WHERE id = ?`,
		id,
	).Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt, &s.RateLimitRPS, &s.RateLimitBurst, &s.BotMode, &s.CertID, &s.CacheEnabled, &s.CacheBySession, &s.SessionCookieName)
	return s, err
}

const metaKeyServicesMigrated = "services_migrated_from_config"

// ConfigApp is the subset of a legacy config.yaml apps: entry needed to
// seed the services table on first startup.
type ConfigApp struct {
	Name, Host, Prefix, Backend string
}

// MigrateConfigApps copies legacy config.yaml apps: entries into the
// services table, exactly once. Safe to call on every startup — after the
// first successful run it's a no-op even if the services table is later
// emptied by the admin.
func (db *DB) MigrateConfigApps(apps []ConfigApp) error {
	done, err := db.getMeta(metaKeyServicesMigrated)
	if err != nil {
		return err
	}
	if done != "" {
		return nil
	}
	for _, a := range apps {
		if err := db.AddService(a.Name, a.Host, a.Prefix, a.Backend, 0, 0); err != nil {
			return fmt.Errorf("migrate app %q: %w", a.Name, err)
		}
	}
	return db.setMeta(metaKeyServicesMigrated, "1")
}

// InsertRequest writes one request log entry and returns the new row ID.
func (db *DB) InsertRequest(r RequestLog) (int64, error) {
	res, err := db.conn.Exec(`
		INSERT INTO requests
			(ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
			 status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
			 request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org,
			 ja3_hash, ja4, visitor_id, bot_score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Timestamp.UTC(),
		r.AppName,
		r.RealIP,
		r.ProxyIP,
		r.Country,
		r.Method,
		r.Host,
		r.Path,
		r.Query,
		r.Status,
		boolToInt(r.Blocked),
		r.RuleID,
		r.Action,
		r.UserAgent,
		r.Duration,
		r.HeadersJSON,
		r.RequestID,
		r.Proto,
		r.TLSVersion,
		r.TLSCipher,
		r.TLSSNI,
		r.ASN,
		r.Org,
		r.JA3Hash,
		r.JA4,
		r.VisitorID,
		r.BotScore,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return id, err
}

// LogDetail is the full representation of one request log row, including
// headers and enrichment fields omitted from list queries for performance.
type LogDetail struct {
	ID          int
	Timestamp   time.Time
	AppName     string
	RealIP      string
	ProxyIP     string
	Country     string
	Method      string
	Host        string
	Path        string
	Query       string
	Status      int
	Blocked     bool
	RuleID      int
	Action      string
	UserAgent   string
	Duration    int64
	HeadersJSON string
	RequestID   string
	Proto       string
	TLSVersion  string
	TLSCipher   string
	TLSSNI      string
	ASN         uint
	Org         string
	JA3Hash     string
	JA4         string
	VisitorID   string
	BotScore    int
}

// GetRequestByID fetches a single request log entry including all enrichment
// fields and headers. Returns sql.ErrNoRows when the id does not exist.
func (db *DB) GetRequestByID(id int) (*LogDetail, error) {
	var d LogDetail
	var blocked int
	err := db.conn.QueryRow(`
		SELECT id, ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
		       status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
		       request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org,
		       ja3_hash, ja4, visitor_id, bot_score
		FROM requests WHERE id = ?`, id).Scan(
		&d.ID, &d.Timestamp, &d.AppName, &d.RealIP, &d.ProxyIP, &d.Country,
		&d.Method, &d.Host, &d.Path, &d.Query,
		&d.Status, &blocked, &d.RuleID, &d.Action, &d.UserAgent, &d.Duration,
		&d.HeadersJSON, &d.RequestID, &d.Proto, &d.TLSVersion, &d.TLSCipher,
		&d.TLSSNI, &d.ASN, &d.Org, &d.JA3Hash, &d.JA4, &d.VisitorID, &d.BotScore,
	)
	if err != nil {
		return nil, err
	}
	d.Blocked = blocked == 1
	return &d, nil
}

// --- Query helpers (used by dashboard later) ---

type Stats struct {
	TotalToday   int
	BlockedToday int
	TotalAll     int
	BlockedAll   int
}

// BotStats holds today's bot-challenge vs clean-pass counts.
type BotStats struct {
	ChallengedToday int // requests redirected to the JS PoW challenge today
	PassedToday     int // requests that reached a backend without being blocked today
}

// AtAGlanceStats contains the live metric strip values shown on the dashboard.
type AtAGlanceStats struct {
	RequestsLastMinute     int
	RequestsPrevMinute     int
	AvgLatencyMS           int
	PrevAvgLatencyMS       int
	BlockedLastMinute      int
	BlockedPrevMinute      int
	WAFRuleHitsToday       int
	WAFRuleHitsPreviousDay int
	UniqueVisitorsToday    int // distinct FingerprintJS visitor IDs since UTC midnight
	UniqueVisitorsPrevDay  int
}

// GetBotStats returns today's bot-challenge count alongside clean (unblocked)
// requests. Same UTC-midnight boundary trick as GetStats — no SQLite date funcs.
func (db *DB) GetBotStats() BotStats {
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var challenged, total, blocked int
	db.conn.QueryRow( //nolint
		`SELECT
			COUNT(*) FILTER (WHERE action = 'bot_challenge'),
			COUNT(*),
			COUNT(*) FILTER (WHERE blocked = 1)
		FROM requests WHERE ts >= ?`, startOfDay,
	).Scan(&challenged, &total, &blocked)
	passed := total - blocked
	if passed < 0 {
		passed = 0
	}
	return BotStats{ChallengedToday: challenged, PassedToday: passed}
}

// GetStats computes today/all-time totals. "Today" is a UTC midnight
// boundary compared with a plain >= rather than SQLite's date()/strftime()
// functions: this driver stores time.Time using Go's default String()
// format ("... +0000 UTC"), which those functions can't parse and would
// silently return NULL (and therefore always-false) for every row.
func (db *DB) GetStats() (Stats, error) {
	var s Stats
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	row := db.conn.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE ts >= ?),
			COUNT(*) FILTER (WHERE ts >= ? AND blocked = 1),
			COUNT(*),
			COUNT(*) FILTER (WHERE blocked = 1)
		FROM requests`, startOfDay, startOfDay)

	err := row.Scan(&s.TotalToday, &s.BlockedToday, &s.TotalAll, &s.BlockedAll)
	return s, err
}

// GetAtAGlanceStats computes compact dashboard metrics without SQLite date
// functions, because requests.ts is stored in Go's time.String() format.
func (db *DB) GetAtAGlanceStats() (AtAGlanceStats, error) {
	now := time.Now().UTC()
	thisMinute := now.Add(-1 * time.Minute)
	prevMinute := now.Add(-2 * time.Minute)
	thisLatency := now.Add(-5 * time.Minute)
	prevLatency := now.Add(-10 * time.Minute)
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	startOfPrevDay := startOfDay.Add(-24 * time.Hour)

	var s AtAGlanceStats
	var avgLatency, prevAvgLatency sql.NullFloat64
	err := db.conn.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE ts >= ?),
			COUNT(*) FILTER (WHERE ts >= ? AND ts < ?),
			AVG(duration_ms) FILTER (WHERE ts >= ?),
			AVG(duration_ms) FILTER (WHERE ts >= ? AND ts < ?),
			COUNT(*) FILTER (WHERE ts >= ? AND blocked = 1),
			COUNT(*) FILTER (WHERE ts >= ? AND ts < ? AND blocked = 1),
			COUNT(*) FILTER (WHERE ts >= ? AND rule_id > 0 AND blocked = 1),
			COUNT(*) FILTER (WHERE ts >= ? AND ts < ? AND rule_id > 0 AND blocked = 1),
			COUNT(DISTINCT visitor_id) FILTER (WHERE ts >= ? AND visitor_id != ''),
			COUNT(DISTINCT visitor_id) FILTER (WHERE ts >= ? AND ts < ? AND visitor_id != '')
		FROM requests`,
		thisMinute,
		prevMinute, thisMinute,
		thisLatency,
		prevLatency, thisLatency,
		thisMinute,
		prevMinute, thisMinute,
		startOfDay,
		startOfPrevDay, startOfDay,
		startOfDay,
		startOfPrevDay, startOfDay,
	).Scan(
		&s.RequestsLastMinute,
		&s.RequestsPrevMinute,
		&avgLatency,
		&prevAvgLatency,
		&s.BlockedLastMinute,
		&s.BlockedPrevMinute,
		&s.WAFRuleHitsToday,
		&s.WAFRuleHitsPreviousDay,
		&s.UniqueVisitorsToday,
		&s.UniqueVisitorsPrevDay,
	)
	if err != nil {
		return AtAGlanceStats{}, err
	}
	if avgLatency.Valid {
		s.AvgLatencyMS = int(avgLatency.Float64 + 0.5)
	}
	if prevAvgLatency.Valid {
		s.PrevAvgLatencyMS = int(prevAvgLatency.Float64 + 0.5)
	}
	return s, nil
}

type LogRow struct {
	ID        int
	Timestamp time.Time
	AppName   string
	RealIP    string
	Country   string
	Method    string
	Host      string
	Path      string
	Status    int
	Blocked   bool
	RuleID    int
	Action    string
	UserAgent string
	Duration  int64
}

// ListRequests returns paginated request logs, newest first.
// Optionally filter by blocked-only or IP.
func (db *DB) ListRequests(blockedOnly bool, ip string, limit, offset int) ([]LogRow, error) {
	query := `SELECT id, ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms
	          FROM requests WHERE 1=1`
	args := []any{}

	if blockedOnly {
		query += " AND blocked = 1"
	}
	if ip != "" {
		query += " AND real_ip = ?"
		args = append(args, ip)
	}
	query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []LogRow
	for rows.Next() {
		var row LogRow
		var blocked int
		if err := rows.Scan(
			&row.ID, &row.Timestamp, &row.AppName, &row.RealIP, &row.Country,
			&row.Method, &row.Host, &row.Path, &row.Status,
			&blocked, &row.RuleID, &row.Action, &row.UserAgent, &row.Duration,
		); err != nil {
			return nil, err
		}
		row.Blocked = blocked == 1
		results = append(results, row)
	}
	return results, rows.Err()
}

// LogFilter describes the search/filter criteria for ListRequestsFiltered.
// Zero values mean "no constraint" for that field.
type LogFilter struct {
	From        time.Time // ts >= From, if non-zero
	To          time.Time // ts <= To, if non-zero
	AppName     string    // exact match, if non-empty
	StatusClass string    // "" | "2xx" | "3xx" | "4xx" | "5xx" | "blocked"
	Limit       int
	Offset      int
}

func (f LogFilter) where() (string, []any) {
	clause := "WHERE 1=1"
	args := []any{}

	if !f.From.IsZero() {
		clause += " AND ts >= ?"
		args = append(args, f.From.UTC())
	}
	if !f.To.IsZero() {
		clause += " AND ts <= ?"
		args = append(args, f.To.UTC())
	}
	if f.AppName != "" {
		clause += " AND app_name = ?"
		args = append(args, f.AppName)
	}
	switch f.StatusClass {
	case "2xx":
		clause += " AND status >= 200 AND status < 300"
	case "3xx":
		clause += " AND status >= 300 AND status < 400"
	case "4xx":
		clause += " AND status >= 400 AND status < 500"
	case "5xx":
		clause += " AND status >= 500"
	case "blocked":
		clause += " AND blocked = 1"
	}
	return clause, args
}

// ListRequestsFiltered returns matching request logs (newest first) plus the
// total count of matching rows (ignoring Limit/Offset), for pagination.
func (db *DB) ListRequestsFiltered(f LogFilter) ([]LogRow, int, error) {
	clause, args := f.where()

	var total int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM requests `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms
	          FROM requests ` + clause + ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), f.Limit, f.Offset)

	rows, err := db.conn.Query(query, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []LogRow
	for rows.Next() {
		var row LogRow
		var blocked int
		if err := rows.Scan(
			&row.ID, &row.Timestamp, &row.AppName, &row.RealIP, &row.Country,
			&row.Method, &row.Host, &row.Path, &row.Status,
			&blocked, &row.RuleID, &row.Action, &row.UserAgent, &row.Duration,
		); err != nil {
			return nil, 0, err
		}
		row.Blocked = blocked == 1
		results = append(results, row)
	}
	return results, total, rows.Err()
}

// HourlyPoint is one bucket of traffic counts for the dashboard chart.
type HourlyPoint struct {
	Hour    time.Time
	Total   int
	Blocked int
}

// GetHourlyTraffic returns per-hour total/blocked counts for the last `hours`
// hours, newest bucket last. Hours with no traffic are omitted; callers
// should fill gaps with zero values for a continuous chart.
//
// Bucketing is done in Go rather than via SQLite's strftime(): this driver
// stores time.Time using Go's default String() format ("... +0000 UTC"),
// which strftime() can't parse and would silently group everything under a
// NULL bucket.
func (db *DB) GetHourlyTraffic(hours int) ([]HourlyPoint, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.conn.Query(`SELECT ts, blocked FROM requests WHERE ts >= ? ORDER BY ts ASC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	buckets := make(map[time.Time]*HourlyPoint)
	var order []time.Time
	for rows.Next() {
		var ts time.Time
		var blocked int
		if err := rows.Scan(&ts, &blocked); err != nil {
			return nil, err
		}
		hour := ts.Truncate(time.Hour)
		p, ok := buckets[hour]
		if !ok {
			p = &HourlyPoint{Hour: hour}
			buckets[hour] = p
			order = append(order, hour)
		}
		p.Total++
		if blocked == 1 {
			p.Blocked++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	points := make([]HourlyPoint, 0, len(order))
	for _, hour := range order {
		points = append(points, *buckets[hour])
	}
	return points, nil
}

// CountryCount is one entry in a top-blocked-countries breakdown.
type CountryCount struct {
	Country string
	Count   int
}

// GetTopBlockedCountries returns the countries with the most blocked
// requests in the last `hours` hours, descending, capped at `limit`.
func (db *DB) GetTopBlockedCountries(limit, hours int) ([]CountryCount, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.conn.Query(`
		SELECT country, COUNT(*) AS c
		FROM requests
		WHERE blocked = 1 AND ts >= ? AND country != ''
		GROUP BY country
		ORDER BY c DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CountryCount
	for rows.Next() {
		var cc CountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

// GetTopCountries returns the countries with the most total requests (blocked
// or allowed) in the last `hours` hours, descending, capped at `limit`.
func (db *DB) GetTopCountries(limit, hours int) ([]CountryCount, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.conn.Query(`
		SELECT country, COUNT(*) AS c
		FROM requests
		WHERE ts >= ? AND country != ''
		GROUP BY country
		ORDER BY c DESC
		LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CountryCount
	for rows.Next() {
		var cc CountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		out = append(out, cc)
	}
	return out, rows.Err()
}

// CountBlockedSince returns the number of blocked requests at or after t.
// Used to drive the notification badge.
func (db *DB) CountBlockedSince(t time.Time) (int, error) {
	var n int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM requests WHERE blocked = 1 AND ts >= ?`, t.UTC()).Scan(&n)
	return n, err
}

// pruneBatchSize bounds how many rows PruneOldRequests deletes per
// transaction. SQLite holds its one process-wide write lock for the whole
// duration of a DELETE — on a large table, a single unbatched
// "DELETE WHERE ts < cutoff" can hold that lock for many seconds, during
// which the async log worker (and any admin-UI write) blocks up to
// busy_timeout and then fails. Chunking keeps each transaction's lock hold
// time small, and the pause between batches gives queued writers a chance
// to run instead of starving behind back-to-back prune transactions.
const pruneBatchSize = 2000

// PruneOldRequests deletes request logs older than `days` days and returns
// how many rows were removed.
func (db *DB) PruneOldRequests(days int) (int64, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	var total int64
	for {
		res, err := db.conn.Exec(
			`DELETE FROM requests WHERE id IN (SELECT id FROM requests WHERE ts < ? LIMIT ?)`,
			cutoff, pruneBatchSize,
		)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < pruneBatchSize {
			return total, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

const metaKeyNotificationsSeenAt = "notifications_seen_at"

// GetOrCreateChallengeSecret returns the HMAC secret used to sign JS challenge
// tokens and bypass cookies. If no secret is stored yet, a random 64-char hex
// string is generated and persisted so it survives restarts (a new secret on
// every restart would invalidate all outstanding bypass cookies).
func (db *DB) GetOrCreateChallengeSecret() (string, error) {
	const key = "challenge_secret"
	secret, err := db.getMeta(key)
	if err == nil && secret != "" {
		return secret, nil
	}
	// Generate a new random secret and persist it.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate challenge secret: %w", err)
	}
	secret = hex.EncodeToString(b)
	return secret, db.setMeta(key, secret)
}

// GetAcmeEmail returns the Let's Encrypt contact email stored in the DB, or
// "" if none has been set yet. Used by the TLS startup path and the admin UI.
func (db *DB) GetAcmeEmail() (string, error) { return db.getMeta("acme_email") }

// GetPrimaryDomain returns the primary domain stored during setup (used for
// ACME host policy so the admin UI domain gets an auto-issued cert).
func (db *DB) GetPrimaryDomain() (string, error) { return db.getMeta("primary_domain") }

// SetPrimaryDomain stores the primary domain for ACME certificate issuance.
func (db *DB) SetPrimaryDomain(domain string) error { return db.setMeta("primary_domain", domain) }

// SetAcmeEmail stores the Let's Encrypt contact email. Must be set before
// any service can use auto-issue TLS.
func (db *DB) SetAcmeEmail(email string) error { return db.setMeta("acme_email", email) }

func (db *DB) getMeta(key string) (string, error) {
	var v string
	err := db.conn.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (db *DB) setMeta(key, value string) error {
	_, err := db.conn.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// NotificationsSeenAt returns the last time the admin marked notifications as
// read. On first ever call (nothing stored yet) it initializes to now, so a
// fresh deployment doesn't immediately show a badge for all historical
// blocked requests.
func (db *DB) NotificationsSeenAt() (time.Time, error) {
	v, err := db.getMeta(metaKeyNotificationsSeenAt)
	if err != nil {
		return time.Time{}, err
	}
	if v == "" {
		now := time.Now().UTC()
		if err := db.setMeta(metaKeyNotificationsSeenAt, now.Format(time.RFC3339Nano)); err != nil {
			return time.Time{}, err
		}
		return now, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

// MarkNotificationsSeen records that the admin has viewed all current
// notifications, resetting the unread badge count going forward.
func (db *DB) MarkNotificationsSeen() error {
	return db.setMeta(metaKeyNotificationsSeenAt, time.Now().UTC().Format(time.RFC3339Nano))
}

// ── Backup ───────────────────────────────────────────────────────────────────

// BackupTo writes a consistent, fully-vacuumed copy of the database to path.
// VACUUM INTO is safe to call while the DB is live — SQLite holds a read lock
// for the duration and writes a fresh, defragmented file.
func (db *DB) BackupTo(path string) error {
	_, err := db.conn.Exec(`VACUUM INTO ?`, path)
	return err
}

// ── Admin auth & sessions ─────────────────────────────────────────────────────

const sessionTTL = 24 * time.Hour

// SeedAdmin sets admin credentials from the CLI setup subcommand. Idempotent —
// on upgrades (credentials already exist) it logs and returns nil without
// overwriting the stored password, so re-running the installer is safe.
func (db *DB) SeedAdmin(email, password string) error {
	existing, _ := db.getMeta("admin_email")
	if existing != "" {
		log.Printf("admin credentials already exist for %s — skipping", existing)
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := db.setMeta("admin_email", email); err != nil {
		return err
	}
	return db.setMeta("admin_password_hash", string(hash))
}

func (db *DB) GetAdminEmail() (string, error) { return db.getMeta("admin_email") }

// UpdateAdminCredentials replaces the stored email and/or password hash.
// Pass empty string for either field to leave it unchanged.
// Invalidates all existing sessions so active sessions can't persist with stale credentials.
func (db *DB) UpdateAdminCredentials(email, newPassword string) error {
	if email != "" {
		if err := db.setMeta("admin_email", email); err != nil {
			return err
		}
	}
	if newPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		if err := db.setMeta("admin_password_hash", string(hash)); err != nil {
			return err
		}
	}
	// Invalidate all sessions — anyone logged in must re-authenticate.
	_, err := db.conn.Exec(`DELETE FROM sessions`)
	return err
}

// CheckAdminPassword validates password against the stored bcrypt hash.
// Returns (false, nil) for any mismatch so callers can't distinguish "no
// user" from "wrong password" — avoids leaking whether an email is registered.
func (db *DB) CheckAdminPassword(password string) (bool, error) {
	hash, err := db.getMeta("admin_password_hash")
	if err != nil || hash == "" {
		return false, err
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

// PruneExpiredSessions deletes session rows past sessionTTL and returns how
// many were removed. Expiry is otherwise only enforced at read time in
// ValidateSession, so abandoned sessions (browser closed without logging
// out) would accumulate forever. created_at is RFC3339 UTC, which compares
// chronologically as a plain string — no SQLite date functions needed.
func (db *DB) PruneExpiredSessions() (int64, error) {
	cutoff := time.Now().UTC().Add(-sessionTTL).Format(time.RFC3339)
	res, err := db.conn.Exec(`DELETE FROM sessions WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CreateSession generates a random token, stores it, and returns it for use
// as a session cookie value.
func (db *DB) CreateSession() (string, error) {
	// Opportunistically sweep expired rows — logins are the only way the
	// table grows, so pruning here keeps it bounded without a background
	// goroutine (the prune CLI covers deployments that never log in again).
	if _, err := db.PruneExpiredSessions(); err != nil {
		log.Printf("session prune: %v", err)
	}
	b := make([]byte, 32)
	rand.Read(b) //nolint — never errors on modern platforms
	token := hex.EncodeToString(b)
	_, err := db.conn.Exec(
		`INSERT INTO sessions (token, created_at) VALUES (?, ?)`,
		token, time.Now().UTC().Format(time.RFC3339),
	)
	return token, err
}

// ValidateSession returns true if the token exists in the DB and was created
// within the last 24 hours.
func (db *DB) ValidateSession(token string) (bool, error) {
	var createdAt string
	err := db.conn.QueryRow(`SELECT created_at FROM sessions WHERE token = ?`, token).Scan(&createdAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	t, parseErr := time.Parse(time.RFC3339, createdAt)
	if parseErr != nil {
		return false, nil
	}
	return time.Since(t) < sessionTTL, nil
}

// DeleteSession removes the token on logout.
func (db *DB) DeleteSession(token string) error {
	_, err := db.conn.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// ── Rate limit state (StateStore impl) ───────────────────────────────────────

// SaveRateLimitState persists all in-memory token-bucket states to SQLite.
// It replaces the whole table in a single transaction — called every 10 s by
// Limiter.StartPersistence so restarts pick up near-current state.
func (db *DB) SaveRateLimitState(states []ratelimit.BucketState) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if _, err := tx.Exec(`DELETE FROM rate_state`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO rate_state (ip, tokens, last_refill) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, s := range states {
		if _, err := stmt.Exec(s.IP, s.Tokens, s.LastRefill.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadRateLimitState reads all persisted bucket states. Called once at startup
// before traffic starts, so there's no concurrency concern.
func (db *DB) LoadRateLimitState() ([]ratelimit.BucketState, error) {
	rows, err := db.conn.Query(`SELECT ip, tokens, last_refill FROM rate_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ratelimit.BucketState
	for rows.Next() {
		var s ratelimit.BucketState
		var ts string
		if err := rows.Scan(&s.IP, &s.Tokens, &ts); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			s.LastRefill = t
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PurgeRateLimitState deletes bucket states whose last_refill is before before,
// keeping the rate_state table from growing unboundedly.
func (db *DB) PurgeRateLimitState(before time.Time) error {
	_, err := db.conn.Exec(
		`DELETE FROM rate_state WHERE last_refill < ?`,
		before.UTC().Format(time.RFC3339Nano),
	)
	return err
}

// GetRedisConfig returns the stored Redis address and password (both empty if
// Redis is not configured and in-memory+SQLite persistence is active).
func (db *DB) GetRedisConfig() (addr, password string, err error) {
	addr, err = db.getMeta("redis_addr")
	if err != nil {
		return
	}
	password, err = db.getMeta("redis_password")
	return
}

// SetRedisConfig persists the Redis backend address and password.
// Pass empty strings to clear the Redis config and revert to in-memory+SQLite.
func (db *DB) SetRedisConfig(addr, password string) error {
	if err := db.setMeta("redis_addr", addr); err != nil {
		return err
	}
	return db.setMeta("redis_password", password)
}

// GetRateLimitSettings reads the global per-client-IP rate limit from the
// meta table. Returns defaults (disabled, 10 rps, burst 20) if never saved
// from the Settings page — global limiting is opt-in like bot protection,
// since a surprise default limit could 429 legitimate NAT'd traffic where
// many users share one IP. Both the memory and Redis backends are built
// from these values.
func (db *DB) GetRateLimitSettings() (enabled bool, rps float64, burst int, err error) {
	rps, burst = 10, 20
	if v, e := db.getMeta("ratelimit_enabled"); e == nil {
		enabled = v == "1"
	}
	if v, e := db.getMeta("ratelimit_rps"); e == nil && v != "" {
		if f, e2 := strconv.ParseFloat(v, 64); e2 == nil && f > 0 {
			rps = f
		}
	}
	if v, e := db.getMeta("ratelimit_burst"); e == nil && v != "" {
		if n, e2 := strconv.Atoi(v); e2 == nil && n > 0 {
			burst = n
		}
	}
	return
}

// SetRateLimitSettings persists the global rate limit to the meta table.
func (db *DB) SetRateLimitSettings(enabled bool, rps float64, burst int) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := db.setMeta("ratelimit_enabled", v); err != nil {
		return err
	}
	if err := db.setMeta("ratelimit_rps", strconv.FormatFloat(rps, 'f', -1, 64)); err != nil {
		return err
	}
	return db.setMeta("ratelimit_burst", strconv.Itoa(burst))
}

// ── Threat intelligence ───────────────────────────────────────────────────────

// ThreatIntelSource is one row from threat_intel_sources.
type ThreatIntelSource struct {
	ID            int64
	Label         string
	URL           string
	IntervalHours int
	Enabled       bool
	LastSyncedAt  time.Time // zero = never synced
	LastError     string
	IPCount       int
	CreatedAt     time.Time
}

func (db *DB) AddThreatIntelSource(label, url string, intervalHours int) error {
	_, err := db.conn.Exec(
		`INSERT INTO threat_intel_sources (label, url, interval_hours) VALUES (?, ?, ?)`,
		label, url, intervalHours,
	)
	return err
}

func (db *DB) DeleteThreatIntelSource(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM threat_intel_sources WHERE id = ?`, id)
	return err
}

func (db *DB) SetThreatIntelSourceEnabled(id int64, enabled bool) error {
	_, err := db.conn.Exec(
		`UPDATE threat_intel_sources SET enabled = ? WHERE id = ?`, boolToInt(enabled), id,
	)
	return err
}

func (db *DB) ListThreatIntelSources() ([]ThreatIntelSource, error) {
	rows, err := db.conn.Query(`
		SELECT id, label, url, interval_hours, enabled,
		       last_synced_at, last_error, ip_count, created_at
		FROM threat_intel_sources ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []ThreatIntelSource
	for rows.Next() {
		var s ThreatIntelSource
		var enabled int
		var lastSyncedStr string
		if err := rows.Scan(&s.ID, &s.Label, &s.URL, &s.IntervalHours, &enabled,
			&lastSyncedStr, &s.LastError, &s.IPCount, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		if lastSyncedStr != "" {
			s.LastSyncedAt = parseTS(lastSyncedStr)
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

// UpdateThreatIntelSync records the outcome of a sync run. On error only the
// timestamp and error message are updated; ip_count is left at its last good
// value so the UI still shows how many IPs were loaded from the previous run.
func (db *DB) UpdateThreatIntelSync(id int64, ipCount int, lastError string) error {
	if lastError != "" {
		_, err := db.conn.Exec(
			`UPDATE threat_intel_sources SET last_synced_at = ?, last_error = ? WHERE id = ?`,
			time.Now().UTC(), lastError, id,
		)
		return err
	}
	_, err := db.conn.Exec(
		`UPDATE threat_intel_sources SET last_synced_at = ?, last_error = '', ip_count = ? WHERE id = ?`,
		time.Now().UTC(), ipCount, id,
	)
	return err
}

// ReplaceThreatIntelIPs atomically replaces all IPs for a source in a single
// transaction so the blocklist never sees a partial update.
func (db *DB) ReplaceThreatIntelIPs(sourceID int64, ips []string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if _, err := tx.Exec(`DELETE FROM threat_intel_ips WHERE source_id = ?`, sourceID); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO threat_intel_ips (source_id, ip) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ip := range ips {
		if _, err := stmt.Exec(sourceID, ip); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListThreatIntelIPs returns all distinct IPs/CIDRs from enabled sources.
// Used by IPBlocklist.Reload to populate the in-memory intel block set.
func (db *DB) ListThreatIntelIPs() ([]string, error) {
	rows, err := db.conn.Query(`
		SELECT DISTINCT ti.ip
		FROM threat_intel_ips ti
		JOIN threat_intel_sources ts ON ti.source_id = ts.id
		WHERE ts.enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ── WAF disabled rules ────────────────────────────────────────────────────────

// DisabledWAFRule is one row from the waf_disabled_rules table.
type DisabledWAFRule struct {
	ID        int64
	RuleID    int
	Reason    string
	CreatedAt time.Time
}

// RuleHit summarises how often a particular WAF rule has fired in request logs.
type RuleHit struct {
	RuleID   int
	HitCount int
	LastSeen time.Time
	Disabled bool // true if the rule is currently in waf_disabled_rules
}

// DisableWAFRule adds (or updates the reason for) a disabled rule.
func (db *DB) DisableWAFRule(ruleID int, reason string) error {
	_, err := db.conn.Exec(
		`INSERT INTO waf_disabled_rules (rule_id, reason)
		 VALUES (?, ?)
		 ON CONFLICT(rule_id) DO UPDATE SET reason = excluded.reason`,
		ruleID, reason,
	)
	return err
}

// EnableWAFRule removes a disabled rule by its row ID.
func (db *DB) EnableWAFRule(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM waf_disabled_rules WHERE id = ?`, id)
	return err
}

// ListDisabledWAFRules returns all disabled rules, newest first.
func (db *DB) ListDisabledWAFRules() ([]DisabledWAFRule, error) {
	rows, err := db.conn.Query(
		`SELECT id, rule_id, reason, created_at FROM waf_disabled_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []DisabledWAFRule
	for rows.Next() {
		var r DisabledWAFRule
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// GetDisabledWAFRuleIDs returns just the rule IDs of all disabled rules.
// Used by the WAF engine to inject SecRuleRemoveById directives at startup.
func (db *DB) GetDisabledWAFRuleIDs() ([]int, error) {
	rows, err := db.conn.Query(`SELECT rule_id FROM waf_disabled_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// tsFormats lists the candidate layouts for parsing timestamps returned by
// SQLite aggregate functions (e.g. MAX(ts)). The driver stores time.Time
// values as strings internally; aggregate results come back as plain strings
// that database/sql won't auto-convert — see the CLAUDE.md SQLite date gotcha.
var tsFormats = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST", // Go time.String() with sub-seconds
	"2006-01-02 15:04:05 -0700 MST",           // Go time.String() exact seconds
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05",
}

func parseTS(s string) time.Time {
	for _, layout := range tsFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetTopFiringRules returns the most-blocked WAF rule IDs from request history,
// annotated with whether each rule is currently disabled.
func (db *DB) GetTopFiringRules(limit int) ([]RuleHit, error) {
	rows, err := db.conn.Query(
		`SELECT rule_id, COUNT(*) AS hit_count, MAX(ts) AS last_seen
		 FROM requests
		 WHERE rule_id > 0 AND blocked = 1
		 GROUP BY rule_id
		 ORDER BY hit_count DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hits []RuleHit
	for rows.Next() {
		var h RuleHit
		var lastSeenStr string
		if err := rows.Scan(&h.RuleID, &h.HitCount, &lastSeenStr); err != nil {
			return nil, err
		}
		h.LastSeen = parseTS(lastSeenStr)
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Mark which rules are currently disabled.
	disabled, _ := db.GetDisabledWAFRuleIDs()
	disabledSet := make(map[int]bool, len(disabled))
	for _, id := range disabled {
		disabledSet[id] = true
	}
	for i := range hits {
		hits[i].Disabled = disabledSet[hits[i].RuleID]
	}
	return hits, nil
}

// ── Webhook ───────────────────────────────────────────────────────────────────

// WebhookConfig is stored in the singleton webhook_config row (id=1).
type WebhookConfig struct {
	URL     string
	Secret  string // sent as X-WAF-Secret header value
	Enabled bool
	Events  string // comma-separated event categories: "blocked", "challenged"
}

func (db *DB) GetWebhookConfig() (WebhookConfig, error) {
	var cfg WebhookConfig
	var enabled int
	err := db.conn.QueryRow(
		`SELECT url, secret, enabled, events FROM webhook_config WHERE id = 1`,
	).Scan(&cfg.URL, &cfg.Secret, &enabled, &cfg.Events)
	if err != nil {
		return WebhookConfig{}, err
	}
	cfg.Enabled = enabled == 1
	return cfg, nil
}

func (db *DB) SetWebhookConfig(cfg WebhookConfig) error {
	_, err := db.conn.Exec(
		`UPDATE webhook_config SET url=?, secret=?, enabled=?, events=? WHERE id=1`,
		cfg.URL, cfg.Secret, boolToInt(cfg.Enabled), cfg.Events,
	)
	return err
}

// ── Email alerts ──────────────────────────────────────────────────────────────

// EmailConfig holds the daily-report email settings. Delivery is
// Cloudflare-only — host, port, username and sender address are hardcoded in
// the mailer package; only the recipient list and the API token are
// configurable. Stored in the meta table and managed from the admin UI — the
// token never lives in config.yaml or the binary.
type EmailConfig struct {
	Enabled bool
	Token   string // Cloudflare API token with Email Sending: Edit (SMTP password)
	To      string // comma-separated recipient list
}

func (db *DB) GetEmailConfig() (EmailConfig, error) {
	var cfg EmailConfig
	enabled, err := db.getMeta("email_enabled")
	if err != nil {
		return EmailConfig{}, err
	}
	cfg.Enabled = enabled == "1"
	if cfg.Token, err = db.getMeta("email_token"); err != nil {
		return EmailConfig{}, err
	}
	if cfg.To, err = db.getMeta("email_to"); err != nil {
		return EmailConfig{}, err
	}
	return cfg, nil
}

func (db *DB) SetEmailConfig(cfg EmailConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	for key, val := range map[string]string{
		"email_enabled": enabled,
		"email_token":   cfg.Token,
		"email_to":      cfg.To,
	} {
		if err := db.setMeta(key, val); err != nil {
			return err
		}
	}
	return nil
}

// GetEmailReportSentFor returns the day ("2006-01-02") the last daily report
// was sent for, so a restart shortly after midnight doesn't send a duplicate.
func (db *DB) GetEmailReportSentFor() (string, error) {
	return db.getMeta("email_report_sent_for")
}

func (db *DB) SetEmailReportSentFor(day string) error {
	return db.setMeta("email_report_sent_for", day)
}

// DailyReport aggregates one reporting window of the requests table for the
// daily alert email.
type DailyReport struct {
	Total            int // all requests in the window
	Blocked          int // requests blocked by any stage
	Status403        int // requests answered with HTTP 403
	UniqueBlockedIPs int // distinct client IPs that had at least one block
	WAFBlocked       int // blocked by a Coraza rule
	IPBlocked        int // blocked by the IP blocklist (manual or threat intel)
	GeoBlocked       int // blocked by a geo rule
	RateLimited      int // rejected by a rate limiter
	BotChallenged    int // served the JS proof-of-work challenge
}

// GetDailyReport crunches [from, to) in a single pass. Time bounds are plain
// comparisons against ts — never SQLite date functions, which can't parse the
// Go time format modernc/sqlite stores (see GetHourlyTraffic).
func (db *DB) GetDailyReport(from, to time.Time) (DailyReport, error) {
	var rep DailyReport
	err := db.conn.QueryRow(`
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE blocked = 1),
		       COUNT(*) FILTER (WHERE status = 403),
		       COUNT(DISTINCT real_ip) FILTER (WHERE blocked = 1),
		       COUNT(*) FILTER (WHERE blocked = 1 AND rule_id > 0),
		       COUNT(*) FILTER (WHERE blocked = 1 AND action LIKE 'ip_blocked%'),
		       COUNT(*) FILTER (WHERE blocked = 1 AND action LIKE 'geo_blocked%'),
		       COUNT(*) FILTER (WHERE blocked = 1 AND action = 'rate_limited'),
		       COUNT(*) FILTER (WHERE action = 'bot_challenge')
		FROM requests WHERE ts >= ? AND ts < ?`,
		from.UTC(), to.UTC(),
	).Scan(&rep.Total, &rep.Blocked, &rep.Status403, &rep.UniqueBlockedIPs,
		&rep.WAFBlocked, &rep.IPBlocked, &rep.GeoBlocked, &rep.RateLimited, &rep.BotChallenged)
	return rep, err
}

// ── Export ────────────────────────────────────────────────────────────────────

// ExportRequests streams all matching request logs through fn. fn returns false
// to stop early. Uses the same LogFilter WHERE clause as ListRequestsFiltered
// but selects all columns and has no pagination cap.
func (db *DB) ExportRequests(f LogFilter, fn func(RequestLog) bool) error {
	where, args := f.where()
	query := `SELECT id, ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
	                 status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
	                 request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org, ja3_hash, ja4, visitor_id, bot_score
	          FROM requests ` + where + ` ORDER BY ts DESC`
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r RequestLog
		var blocked int
		if err := rows.Scan(
			&r.ID, &r.Timestamp, &r.AppName, &r.RealIP, &r.ProxyIP, &r.Country,
			&r.Method, &r.Host, &r.Path, &r.Query,
			&r.Status, &blocked, &r.RuleID, &r.Action, &r.UserAgent, &r.Duration, &r.HeadersJSON,
			&r.RequestID, &r.Proto, &r.TLSVersion, &r.TLSCipher, &r.TLSSNI, &r.ASN, &r.Org, &r.JA3Hash, &r.JA4, &r.VisitorID, &r.BotScore,
		); err != nil {
			return err
		}
		r.Blocked = blocked == 1
		if !fn(r) {
			return nil
		}
	}
	return rows.Err()
}
