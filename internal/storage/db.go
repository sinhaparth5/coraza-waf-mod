package storage

import (
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"coraza-waf-mod/internal/security/ratelimit"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
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
	conn          *sqlx.DB
	dialect       dialect
	logQueue      chan RequestLog
	logDone       chan struct{}
	broadcastFn   func(RequestLog)
	webhookFn     func(RequestLog)
	autobanFn     func(RequestLog)
	threatScoreFn func(RequestLog)
	accessLogFn   func(RequestLog)
	secretGCM     cipher.AEAD // non-nil = secrets-at-rest encryption active (see secretenc.go)
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

// SetAccessLogFn registers a callback invoked (from the log worker goroutine)
// after each successful DB insert. Used to feed the nginx-style access.log
// writer without coupling storage to the accesslog package.
func (db *DB) SetAccessLogFn(fn func(RequestLog)) {
	db.accessLogFn = fn
}

// SetThreatScoreFn registers a callback invoked (from the log worker
// goroutine) after each successful DB insert. Used to feed the unified
// per-IP threat-score subsystem without coupling storage to the
// threatscore package.
func (db *DB) SetThreatScoreFn(fn func(RequestLog)) {
	db.threatScoreFn = fn
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
	CacheStatus string // Varnish X-Cache verdict (HIT/MISS/PASS); "" when the request didn't go through Varnish
}

// Open opens the default SQLite-backed store at path. It is a thin wrapper
// around OpenWithDriver("sqlite", path) kept for backward compatibility with
// every existing caller (main.go's default bootstrap path, every storage
// test) that only ever spoke SQLite before external-database support (issue
// database-backends) was added — none of them need to change.
func Open(path string) (*DB, error) {
	return OpenWithDriver("sqlite", path)
}

// OpenWithDriver opens a store against the given backend. driverName is one
// of "sqlite" (default), "mysql" (also accepts "mariadb"), or "postgres"
// (also accepts "postgresql", "cockroachdb"/"cockroach", or "neon" — all
// four speak the Postgres wire protocol and share the same driver/dialect,
// so there is no separate code path per provider, only DSN differences the
// caller supplies). dsn is a plain SQLite file path for the sqlite dialect,
// or a driver-appropriate connection string for the others (e.g.
// "user:pass@tcp(host:3306)/dbname" for MySQL, "postgres://user:pass@host/db
// ?sslmode=require" for Postgres/CockroachDB/Neon).
func OpenWithDriver(driverName, dsn string) (*DB, error) {
	d, err := resolveDialect(driverName)
	if err != nil {
		return nil, err
	}
	conn, err := d.openDB(dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db := &DB{
		conn:     conn,
		dialect:  d,
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
			if db.threatScoreFn != nil {
				db.threatScoreFn(entry)
			}
			if db.accessLogFn != nil {
				db.accessLogFn(entry)
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

// exec, query, and queryRow are the rebinding equivalents of db.conn's own
// Exec/Query/QueryRow. Every query in this package is written once against
// "?" placeholders; sqlx.DB.Rebind translates that to the target dialect's
// native placeholder syntax before the query reaches the driver — a no-op
// for SQLite and MySQL (both accept "?" natively), but required for
// Postgres, which only understands positional "$1, $2, ..." placeholders
// and returns a syntax error on a literal "?". Centralizing the Rebind call
// here means every existing call site written against "?" keeps working
// unmodified across all three dialects instead of needing its own Rebind.
func (db *DB) exec(query string, args ...any) (sql.Result, error) {
	return db.conn.Exec(db.conn.Rebind(query), args...)
}

func (db *DB) query(query string, args ...any) (*sql.Rows, error) {
	return db.conn.Query(db.conn.Rebind(query), args...)
}

func (db *DB) queryRow(query string, args ...any) *sql.Row {
	return db.conn.QueryRow(db.conn.Rebind(query), args...)
}

// insertReturningID runs an INSERT and returns the id of the new row.
// SQLite and MySQL support this via the driver's LastInsertId(); Postgres
// has no equivalent at the wire-protocol level, so an INSERT there must
// instead append "RETURNING id" and read the new id back like any other
// query result. Every call site's INSERT targets a table whose primary key
// column is literally named "id".
func (db *DB) insertReturningID(query string, args ...any) (int64, error) {
	if db.dialect.name == "postgres" {
		var id int64
		err := db.queryRow(query+" RETURNING id", args...).Scan(&id)
		return id, err
	}
	res, err := db.exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) Close() error {
	close(db.logQueue)
	<-db.logDone
	return db.conn.Close()
}

// schemaMigrations lists every idempotent "ALTER TABLE ... ADD COLUMN ..."
// applied to an existing database on every startup, rendered per dialect via
// dialect.addColumnIfNotExists. Table/column-def pairs, in the same order
// they were historically added as a single hardcoded SQLite string each —
// preserved here so a fresh database and an upgraded one converge on an
// identical schema regardless of dialect.
var schemaMigrations = []struct{ table, columnDef string }{
	{"requests", "country TEXT NOT NULL DEFAULT ''"},
	{"requests", "proxy_ip TEXT NOT NULL DEFAULT ''"},
	{"requests", "headers_json TEXT NOT NULL DEFAULT ''"},
	{"requests", "request_id TEXT NOT NULL DEFAULT ''"},
	{"requests", "proto TEXT NOT NULL DEFAULT ''"},
	{"requests", "tls_version TEXT NOT NULL DEFAULT ''"},
	{"requests", "tls_cipher TEXT NOT NULL DEFAULT ''"},
	{"requests", "tls_sni TEXT NOT NULL DEFAULT ''"},
	{"requests", "asn_num INTEGER NOT NULL DEFAULT 0"},
	{"requests", "org TEXT NOT NULL DEFAULT ''"},
	{"requests", "query TEXT NOT NULL DEFAULT ''"},
	{"requests", "ja3_hash TEXT NOT NULL DEFAULT ''"},
	{"requests", "ja4 TEXT NOT NULL DEFAULT ''"},
	{"requests", "visitor_id TEXT NOT NULL DEFAULT ''"},
	{"requests", "bot_score INTEGER NOT NULL DEFAULT 0"},
	{"requests", "cache_status TEXT NOT NULL DEFAULT ''"},
	{"services", "tls_mode TEXT NOT NULL DEFAULT 'none'"},
	{"services", "tls_cert_path TEXT NOT NULL DEFAULT ''"},
	{"services", "tls_key_path TEXT NOT NULL DEFAULT ''"},
	{"services", "tls_expires_at TEXT NOT NULL DEFAULT ''"},
	{"services", "rate_limit_rps REAL NOT NULL DEFAULT 0"},
	{"services", "rate_limit_burst INTEGER NOT NULL DEFAULT 0"},
	{"services", "bot_mode TEXT NOT NULL DEFAULT 'inherit'"},
	{"services", "cert_id INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_enabled INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_by_session INTEGER NOT NULL DEFAULT 0"},
	{"services", "session_cookie_name TEXT NOT NULL DEFAULT ''"},
	{"services", "cache_ttl_floor INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_ttl_ceiling INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_grace INTEGER NOT NULL DEFAULT 0"},
	{"services", "cache_keep INTEGER NOT NULL DEFAULT 0"},
	{"services", "allow_large_js_uploads INTEGER NOT NULL DEFAULT 0"},
	{"ip_rules", "note TEXT NOT NULL DEFAULT ''"},
	{"webhook_config", "destination_type TEXT NOT NULL DEFAULT 'generic'"},
	{"sessions", "ip TEXT NOT NULL DEFAULT ''"},
	{"sessions", "user_agent TEXT NOT NULL DEFAULT ''"},
	{"sessions", "last_active_at TEXT NOT NULL DEFAULT ''"},
	{"sessions", "revoked_at TEXT NOT NULL DEFAULT ''"},
	{"api_keys", "read_only INTEGER NOT NULL DEFAULT 0"},
	{"services", "request_schema TEXT NOT NULL DEFAULT ''"},
	{"services", "schema_mode TEXT NOT NULL DEFAULT 'off'"},
}

func (db *DB) migrate() error {
	// Idempotent column migration for existing databases. MySQL/Postgres
	// use native "ADD COLUMN IF NOT EXISTS" (see addColumnIfNotExists) and
	// so never actually error here; SQLite has no such clause and always
	// errors with "duplicate column" once a column already exists — that
	// error is expected and intentionally ignored on every startup after
	// the first, exactly as the single hardcoded statements this loop
	// replaced always did (each was itself an ignored, //nolint'd Exec).
	for _, m := range schemaMigrations {
		db.exec(db.dialect.addColumnIfNotExists(m.table, m.columnDef)) //nolint
	}

	for _, stmt := range db.schemaStatements() {
		// CREATE INDEX statements are the one schemaStatements() entry not
		// safely rerunnable on every dialect: MySQL's CREATE INDEX has no
		// IF NOT EXISTS clause at all (see dialect.createIndexIfNotExists/
		// createIndexOnText), so re-running migrate() against an existing
		// MySQL database (e.g. every server restart) always errors
		// "Duplicate key name" here — expected and ignored, the same
		// swallow-the-error convention the ALTER TABLE loop above uses.
		if strings.HasPrefix(stmt, "CREATE INDEX") {
			db.exec(stmt) //nolint
			continue
		}
		if _, err := db.exec(stmt); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}

	// Seed the notifications baseline at startup (not lazily on first access)
	// so a block that happens before any admin page has ever been loaded
	// still counts as "unread" instead of racing the lazy-init.
	metaKeyCol := db.dialect.quoteIdent("key")
	_, err := db.exec(
		db.dialect.upsertIgnore("meta", []string{metaKeyCol, "value"}, "?, ?", []string{metaKeyCol}),
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
	_, err := db.exec(
		db.dialect.upsertUpdate("ip_rules", []string{"app_name", "ip", "rule_type", "note"}, "?, ?, ?, ?",
			[]string{"app_name", "ip"}, []string{"rule_type", "note"}),
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
	err := db.queryRow(
		`SELECT rule_type FROM ip_rules WHERE app_name = ? AND ip = ?`, appName, ip,
	).Scan(&rt)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return rt, err
}

func (db *DB) RemoveIPRule(id int) error {
	_, err := db.exec(`DELETE FROM ip_rules WHERE id = ?`, id)
	return err
}

func (db *DB) ListIPRules() ([]IPRule, error) {
	rows, err := db.query(
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

// ListIPRulesPaginated returns one page of rules (newest first) plus the
// total row count, mirroring ListRequestsFiltered's "COUNT then SELECT ...
// LIMIT ? OFFSET ?" shape — used by the IP Rules admin page so a large,
// autoban-grown ip_rules table is never pulled into memory in one query.
func (db *DB) ListIPRulesPaginated(limit, offset int) ([]IPRule, int, error) {
	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM ip_rules`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.query(
		`SELECT id, app_name, ip, rule_type, note, created_at FROM ip_rules ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.AppName, &r.IP, &r.RuleType, &r.Note, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		rules = append(rules, r)
	}
	return rules, total, rows.Err()
}

// CountIPRulesByType returns the global block/allow counts across the whole
// ip_rules table (not just the current page) — used for the IP Rules page's
// "Rules overview" percentages, which must reflect the full table regardless
// of which page is currently displayed.
func (db *DB) CountIPRulesByType() (blockCount, allowCount int, err error) {
	rows, err := db.query(`SELECT rule_type, COUNT(*) FROM ip_rules GROUP BY rule_type`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var ruleType string
		var n int
		if err := rows.Scan(&ruleType, &n); err != nil {
			return 0, 0, err
		}
		if ruleType == "block" {
			blockCount = n
		} else {
			allowCount = n
		}
	}
	return blockCount, allowCount, rows.Err()
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

// ── Adaptive enforcement config ──────────────────────────────────────────────

// AdaptiveEnforcementConfig controls threat-score-driven adaptive
// enforcement (the adaptive package, issue #16): dynamically scaling the
// global rate limit and forcing a bot challenge based on a client's current
// composite threat score (threatscore package, issue #12). Stored in the
// meta table and managed from the IP Rules page, next to Autoban.
type AdaptiveEnforcementConfig struct {
	Enabled                 bool
	HighRiskThreshold       int     // score >= this: tighten the rate limit
	LowRiskThreshold        int     // score <= this: relax the rate limit
	HighRiskRateScale       float64 // multiplies rate+burst for high-risk IPs, e.g. 0.3
	LowRiskRateScale        float64 // multiplies rate+burst for low-risk IPs, e.g. 1.5
	ForceChallengeThreshold int     // score >= this: force a bot challenge regardless of per-service bot_mode
}

// DefaultAdaptiveEnforcementConfig is used when nothing is stored yet.
// Disabled by default — unlike autoban, this is a brand-new mechanism
// driven by a heuristic composite score (see threatscore's ASN/hosting
// classification) and includes a security-*loosening* action (relaxing
// rate limits for low-risk IPs); an admin should see real scores on the IP
// Rules page before opting in, rather than have enforcement silently start
// adjusting traffic on upgrade.
func DefaultAdaptiveEnforcementConfig() AdaptiveEnforcementConfig {
	return AdaptiveEnforcementConfig{
		Enabled: false, HighRiskThreshold: 70, LowRiskThreshold: 10,
		HighRiskRateScale: 0.3, LowRiskRateScale: 1.5, ForceChallengeThreshold: 70,
	}
}

func (db *DB) GetAdaptiveEnforcementConfig() (AdaptiveEnforcementConfig, error) {
	cfg := DefaultAdaptiveEnforcementConfig()
	if v, err := db.getMeta("adaptive_enabled"); err != nil {
		return cfg, err
	} else if v != "" {
		cfg.Enabled = v == "1"
	}
	if v, _ := db.getMeta("adaptive_high_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.HighRiskThreshold = n
		}
	}
	if v, _ := db.getMeta("adaptive_low_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.LowRiskThreshold = n
		}
	}
	if v, _ := db.getMeta("adaptive_high_rate_scale"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.HighRiskRateScale = f
		}
	}
	if v, _ := db.getMeta("adaptive_low_rate_scale"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.LowRiskRateScale = f
		}
	}
	if v, _ := db.getMeta("adaptive_force_challenge_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.ForceChallengeThreshold = n
		}
	}
	return cfg, nil
}

func (db *DB) SetAdaptiveEnforcementConfig(cfg AdaptiveEnforcementConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("adaptive_enabled", enabled); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_high_threshold", strconv.Itoa(cfg.HighRiskThreshold)); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_low_threshold", strconv.Itoa(cfg.LowRiskThreshold)); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_high_rate_scale", strconv.FormatFloat(cfg.HighRiskRateScale, 'f', -1, 64)); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_low_rate_scale", strconv.FormatFloat(cfg.LowRiskRateScale, 'f', -1, 64)); err != nil {
		return err
	}
	return db.setMeta("adaptive_force_challenge_threshold", strconv.Itoa(cfg.ForceChallengeThreshold))
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
	_, err := db.exec(
		db.dialect.upsertUpdate("geo_rules", []string{"app_name", "country_code", "rule_type"}, "?, ?, ?",
			[]string{"app_name", "country_code"}, []string{"rule_type"}),
		appName, countryCode, ruleType,
	)
	return err
}

func (db *DB) RemoveGeoRule(id int) error {
	_, err := db.exec(`DELETE FROM geo_rules WHERE id = ?`, id)
	return err
}

func (db *DB) ListGeoRules() ([]GeoRule, error) {
	rows, err := db.query(
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
	ID                  int
	Name                string
	Host                string
	Prefix              string
	Backend             string
	CreatedAt           time.Time
	TLSMode             string
	TLSCertPath         string
	TLSKeyPath          string
	TLSExpiresAt        string
	RateLimitRPS        float64
	RateLimitBurst      int
	BotMode             string // "inherit" | "always" | "off"
	CertID              int64  // >0 when TLS cert comes from the shared cert pool
	CacheEnabled        bool   // route clean traffic through the local Varnish cache
	CacheBySession      bool   // partition cached objects by SessionCookieName's value instead of refusing to cache any cookie-bearing request
	SessionCookieName   string // name of this service's session cookie; required for CacheBySession to take effect
	CacheTTLFloor       int    // seconds; 0 = no floor beyond the built-in 1h default for static assets
	CacheTTLCeiling     int    // seconds; 0 = no ceiling, backend Cache-Control wins
	CacheGrace          int    // seconds; 0 = VCL default (30s) — how long a stale object may still be served
	CacheKeep           int    // seconds; 0 = VCL default (30s) — how long a stale object stays around for conditional revalidation after grace
	AllowLargeJSUploads bool   // stream JavaScript request bodies without deep WAF body inspection
	RequestSchema       string // JSON Schema text validated against JSON request bodies; "" disables validation
	SchemaMode          string // "off" | "log" | "enforce" — see waf.Engine.SetRequestSchema
}

func (db *DB) AddService(name, host, prefix, backend string, rps float64, burst int) error {
	_, err := db.exec(
		`INSERT INTO services (name, host, prefix, backend, rate_limit_rps, rate_limit_burst) VALUES (?, ?, ?, ?, ?, ?)`,
		name, host, prefix, backend, rps, burst,
	)
	return err
}

func (db *DB) UpdateService(id int, name, host, prefix, backend string) error {
	_, err := db.exec(
		`UPDATE services SET name = ?, host = ?, prefix = ?, backend = ? WHERE id = ?`,
		name, host, prefix, backend, id,
	)
	return err
}

func (db *DB) RemoveService(id int) error {
	_, err := db.exec(`DELETE FROM services WHERE id = ?`, id)
	return err
}

// SetServiceTLS records a service's TLS configuration. For mode "custom",
// certPath/keyPath point at files on disk (see services.SaveCustomCert);
// for mode "auto" they're left empty since autocert manages its own cache.
func (db *DB) SetServiceTLS(id int, mode, certPath, keyPath, expiresAt string) error {
	_, err := db.exec(
		`UPDATE services SET tls_mode = ?, tls_cert_path = ?, tls_key_path = ?, tls_expires_at = ? WHERE id = ?`,
		mode, certPath, keyPath, expiresAt, id,
	)
	return err
}

// ClearServiceTLS reverts a service to plain HTTP (no TLS), including clearing
// any reference to a pool cert.
func (db *DB) ClearServiceTLS(id int) error {
	_, err := db.exec(
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
	_, err := db.exec(
		`UPDATE services SET cert_id = ?, tls_mode = 'custom', tls_cert_path = '', tls_key_path = '', tls_expires_at = '' WHERE id = ?`,
		certID, serviceID,
	)
	return err
}

// SetServiceRateLimit configures a per-service per-IP rate limit.
// rps=0 disables per-service limiting for this service (falls through to the
// global limiter only).
func (db *DB) SetServiceRateLimit(id int, rps float64, burst int) error {
	_, err := db.exec(
		`UPDATE services SET rate_limit_rps = ?, rate_limit_burst = ? WHERE id = ?`,
		rps, burst, id,
	)
	return err
}

// SetServiceBotMode sets the per-service bot protection override.
// mode must be one of "inherit", "always", or "off".
func (db *DB) SetServiceBotMode(id int, mode string) error {
	_, err := db.exec(`UPDATE services SET bot_mode = ? WHERE id = ?`, mode, id)
	return err
}

// SetServiceLargeJSUploads controls whether JavaScript request bodies for a
// service bypass deep body inspection and stream to its backend. Header-phase
// WAF rules and every other request control remain active.
func (db *DB) SetServiceLargeJSUploads(id int, enabled bool) error {
	_, err := db.exec(`UPDATE services SET allow_large_js_uploads = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

// serviceSchemaModes is the allowed set for Service.SchemaMode. Anything else
// (empty, typo, a value from a future version rolled back) is normalized to
// "off" — the safe, non-blocking default — rather than silently enforcing or
// silently skipping validation depending on what happened to be in the row.
var serviceSchemaModes = map[string]bool{
	"off":     true,
	"log":     true,
	"enforce": true,
}

// SetServiceSchema attaches a JSON Schema to a service's request-body
// validation. schemaJSON is expected to already have been compiled once by
// the caller (waf.ValidateSchema) so a malformed schema is rejected at save
// time rather than discovered during a WAF reload. mode "off" or an empty
// schema disables validation; "log" records violations without blocking;
// "enforce" rejects a mismatching JSON body with 400. See
// waf.Engine.SetRequestSchema for how this is applied per request.
func (db *DB) SetServiceSchema(id int, schemaJSON, mode string) error {
	if !serviceSchemaModes[mode] {
		mode = "off"
	}
	if schemaJSON == "" {
		mode = "off"
	}
	_, err := db.exec(`UPDATE services SET request_schema = ?, schema_mode = ? WHERE id = ?`, schemaJSON, mode, id)
	return err
}

// SetServiceCache toggles routing this service's clean traffic through the
// local Varnish cache. Only takes effect while the global Varnish integration
// (VarnishConfig.Enabled) is on — the flag is kept independent so per-service
// choices survive the cache layer being switched off and on.
func (db *DB) SetServiceCache(id int, enabled bool) error {
	_, err := db.exec(`UPDATE services SET cache_enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

// SetServiceCacheSession configures opt-in session-aware caching for a
// service: when enabled, cached objects are partitioned per session-cookie
// value (see services.Registry's Director and deploy/varnish/default.vcl)
// instead of Varnish refusing to cache any request that carries a cookie.
// cookieName is the name of this service's session cookie; enabled has no
// effect until it's set to a non-empty value.
func (db *DB) SetServiceCacheSession(id int, enabled bool, cookieName string) error {
	_, err := db.exec(`UPDATE services SET cache_by_session = ?, session_cookie_name = ? WHERE id = ?`, boolToInt(enabled), cookieName, id)
	return err
}

// SetServiceCacheTuning configures per-service Varnish TTL/grace/keep
// overrides (see services.Registry's Director and deploy/varnish/default.vcl,
// which read these back as X-Cache-TTL-Floor/-Ceiling/-Grace/-Keep headers).
// Each value is seconds; 0 means "unset", falling back to the VCL's own
// defaults (a 1h floor for static assets, no ceiling, 30s grace/keep).
func (db *DB) SetServiceCacheTuning(id, ttlFloor, ttlCeiling, grace, keep int) error {
	_, err := db.exec(
		`UPDATE services SET cache_ttl_floor = ?, cache_ttl_ceiling = ?, cache_grace = ?, cache_keep = ? WHERE id = ?`,
		ttlFloor, ttlCeiling, grace, keep, id,
	)
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
	return db.insertReturningID(
		`INSERT INTO certificates (name, domains, expires_at, cert_path, key_path) VALUES (?, ?, ?, ?, ?)`,
		name, domains, expiresAt, certPath, keyPath,
	)
}

// UpdateCertificatePaths stores the on-disk file paths after the files have
// been written (called immediately after AddCertificate + SavePoolCert).
func (db *DB) UpdateCertificatePaths(id int64, certPath, keyPath string) error {
	_, err := db.exec(
		`UPDATE certificates SET cert_path = ?, key_path = ? WHERE id = ?`,
		certPath, keyPath, id,
	)
	return err
}

func (db *DB) ListCertificates() ([]CertRecord, error) {
	rows, err := db.query(
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
	err := db.queryRow(
		`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates WHERE id = ?`, id,
	).Scan(&c.ID, &c.Name, &c.Domains, &c.ExpiresAt, &c.CertPath, &c.KeyPath, &c.CreatedAt)
	return c, err
}

// DeleteCertificate removes a cert-pool entry. Services that referenced it
// via cert_id are reset to tls_mode='none' so they don't silently lose TLS.
func (db *DB) DeleteCertificate(id int64) error {
	if _, err := db.exec(
		`UPDATE services SET tls_mode = 'none', cert_id = 0, tls_cert_path = '', tls_key_path = '', tls_expires_at = '' WHERE cert_id = ?`,
		id,
	); err != nil {
		return err
	}
	_, err := db.exec(`DELETE FROM certificates WHERE id = ?`, id)
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

// serviceColumns is shared by ListServices/GetService so their SELECT list
// and Scan args can't drift out of sync as columns are added.
const serviceColumns = `id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at, rate_limit_rps, rate_limit_burst, bot_mode, cert_id, cache_enabled, cache_by_session, session_cookie_name, cache_ttl_floor, cache_ttl_ceiling, cache_grace, cache_keep, allow_large_js_uploads, request_schema, schema_mode`

func (db *DB) scanService(row interface{ Scan(...any) error }) (Service, error) {
	var s Service
	err := row.Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt, &s.RateLimitRPS, &s.RateLimitBurst, &s.BotMode, &s.CertID, &s.CacheEnabled, &s.CacheBySession, &s.SessionCookieName, &s.CacheTTLFloor, &s.CacheTTLCeiling, &s.CacheGrace, &s.CacheKeep, &s.AllowLargeJSUploads, &s.RequestSchema, &s.SchemaMode)
	return s, err
}

func (db *DB) ListServices() ([]Service, error) {
	rows, err := db.query(`SELECT ` + serviceColumns + ` FROM services ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		s, err := db.scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetService fetches a single service by ID.
func (db *DB) GetService(id int) (Service, error) {
	return db.scanService(db.queryRow(`SELECT `+serviceColumns+` FROM services WHERE id = ?`, id))
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
	return db.insertReturningID(`
		INSERT INTO requests
			(ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
			 status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
			 request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org,
			 ja3_hash, ja4, visitor_id, bot_score, cache_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
		r.CacheStatus,
	)
}

// CacheResult counts one service's Varnish verdicts (requests.cache_status)
// over a time window — the per-service view varnishstat can't give, since
// Varnish's own counters are global across every service sharing it.
type CacheResult struct {
	App    string
	Hits   int
	Misses int
	Passes int
}

// CacheResultsSince groups cache verdicts per service for requests at or
// after since. Rows with no verdict (not cache-routed) are excluded.
func (db *DB) CacheResultsSince(since time.Time) ([]CacheResult, error) {
	rows, err := db.query(`
		SELECT app_name,
		       SUM(CASE WHEN cache_status = 'HIT'  THEN 1 ELSE 0 END),
		       SUM(CASE WHEN cache_status = 'MISS' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN cache_status = 'PASS' THEN 1 ELSE 0 END)
		FROM requests
		WHERE ts >= ? AND cache_status != ''
		GROUP BY app_name
		ORDER BY app_name`, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CacheResult
	for rows.Next() {
		var r CacheResult
		if err := rows.Scan(&r.App, &r.Hits, &r.Misses, &r.Passes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
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
	CacheStatus string
}

// GetRequestByID fetches a single request log entry including all enrichment
// fields and headers. Returns sql.ErrNoRows when the id does not exist.
func (db *DB) GetRequestByID(id int) (*LogDetail, error) {
	var d LogDetail
	var blocked int
	err := db.queryRow(`
		SELECT id, ts, app_name, real_ip, proxy_ip, country, method, host, path, query,
		       status, blocked, rule_id, action, user_agent, duration_ms, headers_json,
		       request_id, proto, tls_version, tls_cipher, tls_sni, asn_num, org,
		       ja3_hash, ja4, visitor_id, bot_score, cache_status
		FROM requests WHERE id = ?`, id).Scan(
		&d.ID, &d.Timestamp, &d.AppName, &d.RealIP, &d.ProxyIP, &d.Country,
		&d.Method, &d.Host, &d.Path, &d.Query,
		&d.Status, &blocked, &d.RuleID, &d.Action, &d.UserAgent, &d.Duration,
		&d.HeadersJSON, &d.RequestID, &d.Proto, &d.TLSVersion, &d.TLSCipher,
		&d.TLSSNI, &d.ASN, &d.Org, &d.JA3Hash, &d.JA4, &d.VisitorID, &d.BotScore, &d.CacheStatus,
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
	db.queryRow(
		`SELECT
			COALESCE(SUM(CASE WHEN action LIKE 'bot_challenge%' THEN 1 ELSE 0 END), 0),
			COUNT(*),
			COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0)
		FROM requests WHERE ts >= ?`, startOfDay,
	).Scan(&challenged, &total, &blocked) //nolint
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

	row := db.queryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COUNT(*),
			COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0)
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
	err := db.queryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND ts < ? THEN 1 ELSE 0 END), 0),
			AVG(CASE WHEN ts >= ? THEN duration_ms END),
			AVG(CASE WHEN ts >= ? AND ts < ? THEN duration_ms END),
			COALESCE(SUM(CASE WHEN ts >= ? AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND ts < ? AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND rule_id > 0 AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN ts >= ? AND ts < ? AND rule_id > 0 AND blocked = 1 THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT CASE WHEN ts >= ? AND visitor_id != '' THEN visitor_id END),
			COUNT(DISTINCT CASE WHEN ts >= ? AND ts < ? AND visitor_id != '' THEN visitor_id END)
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

// ListRecentRequestLogs returns up to limit requests since the given time,
// in chronological (oldest first) order — used to preload the access-log
// terminal panel with the last 24h of history instead of starting empty on
// every page load. Unlike LogRow (used by the table view), this returns full
// RequestLog values because accesslog.FormatLine also needs Query and Proto,
// which LogRow doesn't carry.
//
// The DB query itself is ORDER BY ts DESC (so LIMIT keeps the most recent N
// within the window, not the oldest N), then reversed in Go — appending
// these client-side in the returned order reads top-to-bottom like a real
// tail -f, newest at the bottom, matching how live lines get appended.
func (db *DB) ListRecentRequestLogs(since time.Time, limit int) ([]RequestLog, error) {
	rows, err := db.query(
		`SELECT ts, real_ip, method, path, query, proto, status, user_agent
		 FROM requests WHERE ts >= ? ORDER BY ts DESC LIMIT ?`,
		since.UTC(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RequestLog
	for rows.Next() {
		var r RequestLog
		if err := rows.Scan(&r.Timestamp, &r.RealIP, &r.Method, &r.Path, &r.Query, &r.Proto, &r.Status, &r.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
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

	rows, err := db.query(query, args...)
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
	if err := db.queryRow(`SELECT COUNT(*) FROM requests `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT id, ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms
	          FROM requests ` + clause + ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), f.Limit, f.Offset)

	rows, err := db.query(query, qargs...)
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
	rows, err := db.query(`SELECT ts, blocked FROM requests WHERE ts >= ? ORDER BY ts ASC`, since)
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
	rows, err := db.query(`
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
	rows, err := db.query(`
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
	err := db.queryRow(`SELECT COUNT(*) FROM requests WHERE blocked = 1 AND ts >= ?`, t.UTC()).Scan(&n)
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
		res, err := db.exec(
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
	secret, err := db.getSecretMeta(key)
	if err != nil {
		// An unreadable stored secret (wrong/missing --db-key-file) must not
		// be silently replaced with a fresh one — that would invalidate every
		// outstanding bypass cookie and mask the key misconfiguration.
		return "", err
	}
	if secret != "" {
		return secret, nil
	}
	// Generate a new random secret and persist it.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate challenge secret: %w", err)
	}
	secret = hex.EncodeToString(b)
	return secret, db.setSecretMeta(key, secret)
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
	query := fmt.Sprintf(`SELECT value FROM meta WHERE %s = ?`, db.dialect.quoteIdent("key"))
	err := db.queryRow(query, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (db *DB) setMeta(key, value string) error {
	keyCol := db.dialect.quoteIdent("key")
	_, err := db.exec(
		db.dialect.upsertUpdate("meta", []string{keyCol, "value"}, "?, ?", []string{keyCol}, []string{"value"}),
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
	_, err := db.exec(`VACUUM INTO ?`, path)
	return err
}

// Vacuum rebuilds the database in place, returning freed pages to the OS —
// DELETE (e.g. PruneOldRequests) only moves pages to SQLite's free list for
// reuse and never shrinks the file. Meant for the one-shot prune CLI
// (`prune --vacuum`), not the live server: VACUUM is one long write
// transaction, so the running process's log worker would stall behind it for
// the whole rebuild. The TRUNCATE checkpoint afterwards matters because the
// rebuild is written through the WAL — without it the reclaimed space just
// sits in a ballooned -wal file until the last connection closes.
// Vacuum reclaims disk space after a prune. Behavior is dialect-specific:
// SQLite's plain DELETE never shrinks the file (pages are only free-listed
// for reuse), so this runs a full VACUUM rebuild followed by a WAL
// checkpoint truncate — see the "prune --vacuum" one-shot command for why
// this must never run inside the live server. Postgres has its own VACUUM
// with different semantics (reclaims space for reuse in place, no rebuild,
// no WAL-checkpoint-equivalent pragma to run afterward) but supports the
// same bare statement. MySQL has no database-wide VACUUM at all — space
// reclamation there is a per-table OPTIMIZE TABLE, and managed/cloud
// Postgres-family deployments (CockroachDB, Neon) typically handle storage
// reclamation server-side already — so this is a documented no-op for MySQL
// rather than a guess at equivalent behavior.
func (db *DB) Vacuum() error {
	switch db.dialect.name {
	case "mysql":
		return nil
	case "postgres":
		_, err := db.exec(`VACUUM`)
		return err
	default:
		if _, err := db.exec(`VACUUM`); err != nil {
			return err
		}
		_, err := db.exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		return err
	}
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
	_, err := db.exec(`DELETE FROM sessions`)
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

// ── Admin TOTP (two-factor auth) ─────────────────────────────────────────────
//
// All state lives in meta keys, like the credentials above:
//   admin_totp_secret          active base32 secret ("" = 2FA disabled)
//   admin_totp_pending_secret  enrollment in progress, not yet confirmed
//   admin_totp_backup_codes    comma-separated SHA-256 hex digests, removed on use
//   admin_totp_last_counter    last accepted TOTP counter, to reject replays

// GetTOTPSecret returns the active TOTP secret, or "" when 2FA is disabled.
func (db *DB) GetTOTPSecret() (string, error) { return db.getSecretMeta("admin_totp_secret") }

// TOTPEnabled reports whether admin login requires a second factor. Reads the
// raw value: "is 2FA on" doesn't need the secret decrypted, so it keeps
// working (and keeps the login flow demanding a second factor) even when the
// key file is missing — failing open to password-only here would let a key
// misconfiguration disable 2FA.
func (db *DB) TOTPEnabled() (bool, error) {
	s, err := db.getMeta("admin_totp_secret")
	return s != "", err
}

// SetPendingTOTPSecret stores a not-yet-confirmed enrollment secret. It only
// becomes active via EnableTOTP after the admin proves their authenticator
// produces a valid code; a stale pending secret is inert.
func (db *DB) SetPendingTOTPSecret(secret string) error {
	return db.setSecretMeta("admin_totp_pending_secret", secret)
}

// GetPendingTOTPSecret returns the enrollment secret awaiting confirmation.
func (db *DB) GetPendingTOTPSecret() (string, error) {
	return db.getSecretMeta("admin_totp_pending_secret")
}

// EnableTOTP promotes the pending secret to active and stores the backup-code
// hashes (SHA-256 hex — the codes are high-entropy random, so like API keys
// they don't need bcrypt). Returns an error if no enrollment is pending.
func (db *DB) EnableTOTP(backupHashes []string) error {
	pending, err := db.getSecretMeta("admin_totp_pending_secret")
	if err != nil {
		return err
	}
	if pending == "" {
		return fmt.Errorf("no pending TOTP enrollment")
	}
	if err := db.setSecretMeta("admin_totp_secret", pending); err != nil {
		return err
	}
	if err := db.setMeta("admin_totp_backup_codes", strings.Join(backupHashes, ",")); err != nil {
		return err
	}
	if err := db.setMeta("admin_totp_last_counter", ""); err != nil {
		return err
	}
	return db.setMeta("admin_totp_pending_secret", "")
}

// DisableTOTP clears the secret, backup codes, and any pending enrollment.
func (db *DB) DisableTOTP() error {
	for _, key := range []string{
		"admin_totp_secret", "admin_totp_pending_secret",
		"admin_totp_backup_codes", "admin_totp_last_counter",
	} {
		if err := db.setMeta(key, ""); err != nil {
			return err
		}
	}
	return nil
}

// ConsumeTOTPBackupCode removes hash from the stored backup codes and reports
// whether it was present — each code works exactly once.
func (db *DB) ConsumeTOTPBackupCode(hash string) (bool, error) {
	stored, err := db.getMeta("admin_totp_backup_codes")
	if err != nil || stored == "" {
		return false, err
	}
	codes := strings.Split(stored, ",")
	for i, c := range codes {
		if c == hash {
			codes = append(codes[:i], codes[i+1:]...)
			return true, db.setMeta("admin_totp_backup_codes", strings.Join(codes, ","))
		}
	}
	return false, nil
}

// GetTOTPLastCounter returns the counter of the last accepted TOTP code
// (0 when none has been accepted yet).
func (db *DB) GetTOTPLastCounter() (uint64, error) {
	v, err := db.getMeta("admin_totp_last_counter")
	if err != nil || v == "" {
		return 0, err
	}
	n, parseErr := strconv.ParseUint(v, 10, 64)
	if parseErr != nil {
		return 0, nil
	}
	return n, nil
}

// SetTOTPLastCounter records the counter of an accepted code so the same
// code can't be replayed within its validity window.
func (db *DB) SetTOTPLastCounter(counter uint64) error {
	return db.setMeta("admin_totp_last_counter", strconv.FormatUint(counter, 10))
}

// ── Admin passkeys (WebAuthn, issue #78) ─────────────────────────────────────
//
// A second, browser/authenticator-backed factor alongside TOTP — see
// internal/security/passkey. Unlike the single TOTP secret, an admin
// normally registers more than one passkey (phone, laptop, security key),
// so these live in their own table rather than a meta key.

// WebAuthnCredential is one registered passkey.
type WebAuthnCredential struct {
	ID           int64
	CredentialID string // base64url(credential.ID), for fast lookup
	Data         []byte // JSON-encoded webauthn.Credential
	Name         string
	CreatedAt    time.Time
	LastUsedAt   string
}

// GetOrCreateWebAuthnHandle returns the stable, opaque WebAuthn user handle
// for the single admin account, generating and persisting one (32 random
// bytes) on first use. It is not a secret — knowing it alone proves
// nothing — just a stable non-PII identifier the spec requires, so it's
// stored as plain meta rather than via getSecretMeta/setSecretMeta.
func (db *DB) GetOrCreateWebAuthnHandle() ([]byte, error) {
	s, err := db.getMeta("admin_webauthn_handle")
	if err != nil {
		return nil, err
	}
	if s != "" {
		return base64.StdEncoding.DecodeString(s)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := db.setMeta("admin_webauthn_handle", base64.StdEncoding.EncodeToString(b)); err != nil {
		return nil, err
	}
	return b, nil
}

// WebAuthnEnabled reports whether the admin has at least one registered
// passkey — the login page only offers the passkey option, and LoginPost
// only demands a second factor for passkey-only admins, when this is true.
func (db *DB) WebAuthnEnabled() (bool, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM webauthn_credentials`).Scan(&n)
	return n > 0, err
}

// ListWebAuthnCredentials returns every registered passkey, newest first.
func (db *DB) ListWebAuthnCredentials() ([]WebAuthnCredential, error) {
	rows, err := db.query(
		`SELECT id, credential_id, data, name, created_at, last_used_at FROM webauthn_credentials ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var data string
		if err := rows.Scan(&c.ID, &c.CredentialID, &data, &c.Name, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		c.Data = []byte(data)
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddWebAuthnCredential stores a newly registered passkey.
func (db *DB) AddWebAuthnCredential(credentialID, name string, data []byte) error {
	_, err := db.exec(
		`INSERT INTO webauthn_credentials (credential_id, data, name, created_at) VALUES (?, ?, ?, ?)`,
		credentialID, string(data), name, time.Now(),
	)
	return err
}

// TouchWebAuthnCredential updates a credential's stored data (its sign
// counter changes on every successful login, guarding against a cloned
// authenticator) and last-used timestamp after a successful login.
func (db *DB) TouchWebAuthnCredential(credentialID string, data []byte) error {
	_, err := db.exec(
		`UPDATE webauthn_credentials SET data = ?, last_used_at = ? WHERE credential_id = ?`,
		string(data), time.Now().UTC().Format(time.RFC3339), credentialID,
	)
	return err
}

// DeleteWebAuthnCredential removes one registered passkey by its row id.
func (db *DB) DeleteWebAuthnCredential(id int64) error {
	_, err := db.exec(`DELETE FROM webauthn_credentials WHERE id = ?`, id)
	return err
}

// sessionHistoryTTL is how long a session row survives after it was
// created. It is deliberately much longer than sessionTTL: a row stops
// authenticating anything after sessionTTL, but is kept as the device
// history the Settings page's "Registered devices" card lists, so an admin
// can still see where the account was logged in last month.
const sessionHistoryTTL = 30 * 24 * time.Hour

// PruneExpiredSessions deletes session rows past sessionHistoryTTL and
// returns how many were removed — without it, rows would accumulate
// forever. created_at is RFC3339 UTC, which compares chronologically as a
// plain string, so no SQLite date functions are needed (see the date/time
// gotcha in CLAUDE.md).
func (db *DB) PruneExpiredSessions() (int64, error) {
	cutoff := time.Now().UTC().Add(-sessionHistoryTTL).Format(time.RFC3339)
	res, err := db.exec(`DELETE FROM sessions WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Session is one row of the sessions table: a single admin login on a
// single device. There is no user_id — this deployment has exactly one
// admin account (credentials live in meta), so every row belongs to it.
type Session struct {
	Token        string
	CreatedAt    time.Time
	IP           string
	UserAgent    string
	LastActiveAt time.Time
	RevokedAt    time.Time // zero value = never revoked
}

// Revoked reports whether the session was explicitly ended — by logging
// out, by being revoked from the Settings page, or by being superseded by a
// newer login. Distinct from Expired so the login page can tell the admin
// which of the two happened.
func (s *Session) Revoked() bool { return !s.RevokedAt.IsZero() }

// Expired reports whether the session aged out of sessionTTL.
func (s *Session) Expired() bool { return time.Since(s.CreatedAt) >= sessionTTL }

// Live reports whether the session still authenticates requests.
func (s *Session) Live() bool { return !s.Revoked() && !s.Expired() }

// parseSessionTime maps the empty string (a column default, i.e. "never")
// onto the zero time rather than an error.
func parseSessionTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// CreateSession generates a random token, stores it, and returns it for use
// as a session cookie value.
//
// An account may only have one live session at a time, so this first
// revokes every session that is currently live: logging in on a new device
// immediately signs the old one out, and the old device is told why on its
// next request (see Session.Revoked). The legitimate owner can therefore
// always take back an account someone else is sitting on, which is the
// point — the alternative (refusing the new login while an old session
// lives) locks the owner out until the intruder's session happens to
// expire.
func (db *DB) CreateSession(ip, userAgent string) (string, error) {
	// Opportunistically sweep aged-out rows — logins are the only way the
	// table grows, so pruning here keeps it bounded without a background
	// goroutine (the prune CLI covers deployments that never log in again).
	if _, err := db.PruneExpiredSessions(); err != nil {
		log.Printf("session prune: %v", err)
	}
	b := make([]byte, 32)
	rand.Read(b) //nolint — never errors on modern platforms
	token := hex.EncodeToString(b)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.exec(`UPDATE sessions SET revoked_at = ? WHERE revoked_at = ''`, now); err != nil {
		return "", err
	}
	_, err := db.exec(
		`INSERT INTO sessions (token, created_at, ip, user_agent, last_active_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, '')`,
		token, now, ip, userAgent, now,
	)
	return token, err
}

// GetSession returns the row for token, or nil if there is none. Whether
// the session still authenticates anything is the caller's decision — see
// Session.Live/Revoked/Expired, which the login page uses to explain to a
// signed-out admin which of the two happened.
func (db *DB) GetSession(token string) (*Session, error) {
	var s Session
	var created, lastActive, revoked string
	err := db.queryRow(
		`SELECT token, created_at, ip, user_agent, last_active_at, revoked_at
		 FROM sessions WHERE token = ?`, token,
	).Scan(&s.Token, &created, &s.IP, &s.UserAgent, &lastActive, &revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt = parseSessionTime(created)
	s.LastActiveAt = parseSessionTime(lastActive)
	s.RevokedAt = parseSessionTime(revoked)
	return &s, nil
}

// ValidateSession reports whether the token authenticates a request.
func (db *DB) ValidateSession(token string) (bool, error) {
	s, err := db.GetSession(token)
	if err != nil || s == nil {
		return false, err
	}
	return s.Live(), nil
}

// TouchSession records that the session was just used. Called off the hot
// path and throttled by the caller, like TouchAPIKey.
func (db *DB) TouchSession(token string) error {
	_, err := db.exec(
		`UPDATE sessions SET last_active_at = ? WHERE token = ?`,
		time.Now().UTC().Format(time.RFC3339), token,
	)
	return err
}

// ListSessions returns every session row for the Settings page's
// "Registered devices" card: the live session first (which, given one live
// session is enforced at login, is the caller's own device), then signed-out
// devices newest first. Ordering on the boolean is portable across all three
// dialects — SQLite and MySQL yield 1/0, Postgres a real boolean, and DESC
// puts true first in every case. Without it, two logins landing in the same
// RFC3339 second could list the current device below a dead one.
func (db *DB) ListSessions() ([]Session, error) {
	rows, err := db.query(
		`SELECT token, created_at, ip, user_agent, last_active_at, revoked_at
		 FROM sessions ORDER BY (revoked_at = '') DESC, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		var created, lastActive, revoked string
		if err := rows.Scan(&s.Token, &created, &s.IP, &s.UserAgent, &lastActive, &revoked); err != nil {
			return nil, err
		}
		s.CreatedAt = parseSessionTime(created)
		s.LastActiveAt = parseSessionTime(lastActive)
		s.RevokedAt = parseSessionTime(revoked)
		out = append(out, s)
	}
	return out, rows.Err()
}

// RevokeSession ends one session without deleting its history row.
func (db *DB) RevokeSession(token string) error {
	_, err := db.exec(
		`UPDATE sessions SET revoked_at = ? WHERE token = ? AND revoked_at = ''`,
		time.Now().UTC().Format(time.RFC3339), token,
	)
	return err
}

// RevokeOtherSessions ends every live session except keep. With one live
// session enforced at login this is normally a no-op, and exists for the
// "Log out of all other devices" button to be honest anyway — a row could
// still be live if it was created before this rule shipped.
func (db *DB) RevokeOtherSessions(keep string) (int64, error) {
	res, err := db.exec(
		`UPDATE sessions SET revoked_at = ? WHERE revoked_at = '' AND token <> ?`,
		time.Now().UTC().Format(time.RFC3339), keep,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteSession removes the token on logout. Logging out deliberately drops
// the row rather than revoking it: an admin who signs out on purpose does
// not need that device listed back at them as history.
func (db *DB) DeleteSession(token string) error {
	_, err := db.exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// ── API keys ──────────────────────────────────────────────────────────────────

// APIKey is a row in the api_keys table. The raw key is never stored — only
// key_hash (a SHA-256 hex digest, computed by the caller) and key_prefix (a
// short, non-secret slice of the raw key kept for display so an admin can
// tell keys apart in the UI without ever seeing the secret again).
type APIKey struct {
	ID         int
	Name       string
	Prefix     string
	ReadOnly   bool // true: GET endpoints only, every mutating route 403s (see ui.requireWrite)
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// CreateAPIKey stores a new key and returns its row id. hash is the SHA-256
// hex digest of the raw key; the raw key itself is shown to the admin exactly
// once by the caller and never persisted.
func (db *DB) CreateAPIKey(name, prefix, hash string, readOnly bool) (int, error) {
	id, err := db.insertReturningID(
		`INSERT INTO api_keys (name, key_prefix, key_hash, read_only) VALUES (?, ?, ?, ?)`,
		name, prefix, hash, boolToInt(readOnly),
	)
	return int(id), err
}

// ListAPIKeys returns every key's metadata, newest first. key_hash is
// intentionally never selected.
func (db *DB) ListAPIKeys() ([]APIKey, error) {
	rows, err := db.query(
		`SELECT id, name, key_prefix, read_only, created_at, last_used_at FROM api_keys ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		var lastUsed sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.ReadOnly, &k.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			k.LastUsedAt = &lastUsed.Time
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RemoveAPIKey revokes a key by hard-deleting its row — matching this
// codebase's existing no-soft-delete convention (RemoveService, RemoveIPRule).
func (db *DB) RemoveAPIKey(id int) error {
	_, err := db.exec(`DELETE FROM api_keys WHERE id = ?`, id)
	return err
}

// ValidateAPIKey looks up a key by its SHA-256 hash. It returns (nil, nil)
// when no key matches — not an error — so callers can distinguish "invalid
// key" from a DB failure.
func (db *DB) ValidateAPIKey(hash string) (*APIKey, error) {
	var k APIKey
	var lastUsed sql.NullTime
	err := db.queryRow(
		`SELECT id, name, key_prefix, read_only, created_at, last_used_at FROM api_keys WHERE key_hash = ?`, hash,
	).Scan(&k.ID, &k.Name, &k.Prefix, &k.ReadOnly, &k.CreatedAt, &lastUsed)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		k.LastUsedAt = &lastUsed.Time
	}
	return &k, nil
}

// TouchAPIKey records that a key was just used to authenticate a request.
// Callers should throttle how often this is invoked per key (see
// ui.apiKeyAuth) rather than calling it on every request.
func (db *DB) TouchAPIKey(id int) error {
	_, err := db.exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().UTC(), id)
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
	stmt, err := tx.Prepare(db.conn.Rebind(`INSERT INTO rate_state (ip, tokens, last_refill) VALUES (?, ?, ?)`))
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
	rows, err := db.query(`SELECT ip, tokens, last_refill FROM rate_state`)
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
	_, err := db.exec(
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
	password, err = db.getSecretMeta("redis_password")
	return
}

// SetRedisConfig persists the Redis backend address and password.
// Pass empty strings to clear the Redis config and revert to in-memory+SQLite.
func (db *DB) SetRedisConfig(addr, password string) error {
	if err := db.setMeta("redis_addr", addr); err != nil {
		return err
	}
	return db.setSecretMeta("redis_password", password)
}

// TypeSafeConfig holds the opt-in settings for TypeSafe-backed ASN/hosting
// classification (internal/security/threatscore/typesafeclassify.go), which
// refines the hardcoded heuristic in asnclass.go for ASN organization names
// it doesn't recognize. Disabled by default: the heuristic works with no
// config at all, and enabling this adds an external API dependency and a
// credential to manage.
type TypeSafeConfig struct {
	Enabled bool
	APIKey  string
}

func (db *DB) GetTypeSafeConfig() (TypeSafeConfig, error) {
	var cfg TypeSafeConfig
	enabled, err := db.getMeta("typesafe_enabled")
	if err != nil {
		return TypeSafeConfig{}, err
	}
	cfg.Enabled = enabled == "1"
	if cfg.APIKey, err = db.getSecretMeta("typesafe_api_key"); err != nil {
		return TypeSafeConfig{}, err
	}
	return cfg, nil
}

// SetTypeSafeConfig persists the TypeSafe enable flag and API key.
func (db *DB) SetTypeSafeConfig(cfg TypeSafeConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("typesafe_enabled", enabled); err != nil {
		return err
	}
	return db.setSecretMeta("typesafe_api_key", cfg.APIKey)
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
	_, err := db.exec(
		`INSERT INTO threat_intel_sources (label, url, interval_hours) VALUES (?, ?, ?)`,
		label, url, intervalHours,
	)
	return err
}

func (db *DB) DeleteThreatIntelSource(id int64) error {
	_, err := db.exec(`DELETE FROM threat_intel_sources WHERE id = ?`, id)
	return err
}

func (db *DB) SetThreatIntelSourceEnabled(id int64, enabled bool) error {
	_, err := db.exec(
		`UPDATE threat_intel_sources SET enabled = ? WHERE id = ?`, boolToInt(enabled), id,
	)
	return err
}

func (db *DB) ListThreatIntelSources() ([]ThreatIntelSource, error) {
	rows, err := db.query(`
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
		_, err := db.exec(
			`UPDATE threat_intel_sources SET last_synced_at = ?, last_error = ? WHERE id = ?`,
			time.Now().UTC(), lastError, id,
		)
		return err
	}
	_, err := db.exec(
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
	if _, err := tx.Exec(db.conn.Rebind(`DELETE FROM threat_intel_ips WHERE source_id = ?`), sourceID); err != nil {
		return err
	}
	insertStmt := db.dialect.upsertIgnore("threat_intel_ips", []string{"source_id", "ip"}, "?, ?", []string{"source_id", "ip"})
	stmt, err := tx.Prepare(db.conn.Rebind(insertStmt))
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
	rows, err := db.query(`
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
	_, err := db.exec(
		db.dialect.upsertUpdate("waf_disabled_rules", []string{"rule_id", "reason"}, "?, ?",
			[]string{"rule_id"}, []string{"reason"}),
		ruleID, reason,
	)
	return err
}

// EnableWAFRule removes a disabled rule by its row ID.
func (db *DB) EnableWAFRule(id int64) error {
	_, err := db.exec(`DELETE FROM waf_disabled_rules WHERE id = ?`, id)
	return err
}

// ListDisabledWAFRules returns all disabled rules, newest first.
func (db *DB) ListDisabledWAFRules() ([]DisabledWAFRule, error) {
	rows, err := db.query(
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
	rows, err := db.query(`SELECT rule_id FROM waf_disabled_rules`)
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

// ── WAF per-service rule exceptions ─────────────────────────────────────────
//
// A separate table rather than a service_name column on waf_disabled_rules:
// that table's rule_id column is UNIQUE (one row per rule ID, ever), so the
// same rule can't also have a service-scoped row without a constraint change
// SQLite can't do via ALTER TABLE. This mirrors the ip_threat_scores/
// ja4_reputation precedent — a new bolt-on table instead of reshaping an
// existing one.

// WAFServiceException is one row from the waf_service_rule_exceptions table:
// a CRS rule disabled for a single service rather than globally.
type WAFServiceException struct {
	ID          int64
	ServiceName string
	RuleID      int
	Reason      string
	CreatedAt   time.Time
}

// DisableWAFRuleForService adds (or updates the reason for) a rule exception
// scoped to one service.
func (db *DB) DisableWAFRuleForService(serviceName string, ruleID int, reason string) error {
	_, err := db.exec(
		db.dialect.upsertUpdate("waf_service_rule_exceptions", []string{"service_name", "rule_id", "reason"}, "?, ?, ?",
			[]string{"service_name", "rule_id"}, []string{"reason"}),
		serviceName, ruleID, reason,
	)
	return err
}

// EnableWAFRuleForService removes a per-service rule exception by its row ID.
func (db *DB) EnableWAFRuleForService(id int64) error {
	_, err := db.exec(`DELETE FROM waf_service_rule_exceptions WHERE id = ?`, id)
	return err
}

// ListWAFServiceExceptions returns all per-service rule exceptions, newest first.
func (db *DB) ListWAFServiceExceptions() ([]WAFServiceException, error) {
	rows, err := db.query(
		`SELECT id, service_name, rule_id, reason, created_at
		 FROM waf_service_rule_exceptions ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exceptions []WAFServiceException
	for rows.Next() {
		var e WAFServiceException
		if err := rows.Scan(&e.ID, &e.ServiceName, &e.RuleID, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		exceptions = append(exceptions, e)
	}
	return exceptions, rows.Err()
}

// GetWAFRuleIDsForService returns the rule IDs disabled specifically for
// serviceName. It does not include globally-disabled rules — callers union
// this with GetDisabledWAFRuleIDs themselves.
func (db *DB) GetWAFRuleIDsForService(serviceName string) ([]int, error) {
	rows, err := db.query(
		`SELECT rule_id FROM waf_service_rule_exceptions WHERE service_name = ?`, serviceName,
	)
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

// ListWAFExceptionServiceNames returns the distinct service names that have
// at least one per-service rule exception. Used to know which services need
// their own compiled WAF engine on top of the shared default one.
func (db *DB) ListWAFExceptionServiceNames() ([]string, error) {
	rows, err := db.query(`SELECT DISTINCT service_name FROM waf_service_rule_exceptions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// ── WAF rule feedback (issue #76) ───────────────────────────────────────────
//
// Suggestion-only signal collection: an admin marks a blocked request's rule
// as a false or true positive from the Logs page (MarkWAFRuleFeedback).
// GetWAFRuleSuggestions surfaces (service, rule) pairs with enough
// false-positive marks and no true-positive marks in a rolling window as a
// one-click "add exception" prompt on the WAF Rules page — it never disables
// a rule itself, only DisableWAFRule/DisableWAFRuleForService do that.

// MarkWAFRuleFeedback records one false/true-positive mark for a blocked
// request's rule, scoped to the service it hit (serviceName is "" for
// unmatched-host/global traffic, matching RequestLog.AppName).
func (db *DB) MarkWAFRuleFeedback(serviceName string, ruleID int, falsePositive bool) error {
	_, err := db.exec(
		`INSERT INTO waf_rule_feedback (service_name, rule_id, false_positive) VALUES (?, ?, ?)`,
		serviceName, ruleID, boolToInt(falsePositive),
	)
	return err
}

// WAFRuleFeedbackConfig controls the false-positive-mark threshold/window
// GetWAFRuleSuggestions uses. Stored in meta, mirrors AutobanConfig's shape.
type WAFRuleFeedbackConfig struct {
	Threshold  int // false-positive marks needed within the window, with zero true-positive marks
	WindowDays int // rolling window size
}

// DefaultWAFRuleFeedbackConfig is used when nothing is stored yet: suggest
// after 5 false-positive marks in 7 days.
func DefaultWAFRuleFeedbackConfig() WAFRuleFeedbackConfig {
	return WAFRuleFeedbackConfig{Threshold: 5, WindowDays: 7}
}

func (db *DB) GetWAFRuleFeedbackConfig() (WAFRuleFeedbackConfig, error) {
	cfg := DefaultWAFRuleFeedbackConfig()
	if v, err := db.getMeta("waf_feedback_threshold"); err != nil {
		return cfg, err
	} else if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Threshold = n
		}
	}
	if v, _ := db.getMeta("waf_feedback_window_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.WindowDays = n
		}
	}
	return cfg, nil
}

func (db *DB) SetWAFRuleFeedbackConfig(cfg WAFRuleFeedbackConfig) error {
	if err := db.setMeta("waf_feedback_threshold", strconv.Itoa(cfg.Threshold)); err != nil {
		return err
	}
	return db.setMeta("waf_feedback_window_days", strconv.Itoa(cfg.WindowDays))
}

// WAFRuleSuggestion is one (service, rule) pair with enough false-positive
// marks and no true-positive marks in the configured window to suggest
// adding an exception for it.
type WAFRuleSuggestion struct {
	ServiceName        string // "" = global/unmatched-host traffic
	RuleID             int
	FalsePositiveCount int
	LastMarked         time.Time
}

// GetWAFRuleSuggestions aggregates waf_rule_feedback within cfg.WindowDays
// and returns pairs at or above cfg.Threshold false-positive marks with zero
// true-positive marks in that same window, excluding any pair that already
// has an exception (global or per-service) — suggesting one for a rule
// that's already suppressed for that service would be a dead-end button.
func (db *DB) GetWAFRuleSuggestions(cfg WAFRuleFeedbackConfig) ([]WAFRuleSuggestion, error) {
	cutoff := time.Now().Add(-time.Duration(cfg.WindowDays) * 24 * time.Hour)
	rows, err := db.query(
		`SELECT service_name, rule_id,
		        SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) AS fp,
		        SUM(CASE WHEN false_positive = 0 THEN 1 ELSE 0 END) AS tp,
		        MAX(created_at) AS last_marked
		 FROM waf_rule_feedback
		 WHERE created_at >= ?
		 GROUP BY service_name, rule_id`,
		cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type ruleKey struct {
		service string
		ruleID  int
	}
	var candidates []WAFRuleSuggestion
	seen := make(map[ruleKey]bool)
	for rows.Next() {
		var svc string
		var ruleID, fp, tp int
		var lastMarkedStr string
		if err := rows.Scan(&svc, &ruleID, &fp, &tp, &lastMarkedStr); err != nil {
			return nil, err
		}
		if fp < cfg.Threshold || tp > 0 {
			continue
		}
		key := ruleKey{svc, ruleID}
		if seen[key] {
			continue
		}
		seen[key] = true
		candidates = append(candidates, WAFRuleSuggestion{
			ServiceName:        svc,
			RuleID:             ruleID,
			FalsePositiveCount: fp,
			LastMarked:         parseTS(lastMarkedStr),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	globalDisabled, err := db.GetDisabledWAFRuleIDs()
	if err != nil {
		return nil, err
	}
	globalSet := make(map[int]bool, len(globalDisabled))
	for _, id := range globalDisabled {
		globalSet[id] = true
	}
	exceptions, err := db.ListWAFServiceExceptions()
	if err != nil {
		return nil, err
	}
	exceptionSet := make(map[ruleKey]bool, len(exceptions))
	for _, e := range exceptions {
		exceptionSet[ruleKey{e.ServiceName, e.RuleID}] = true
	}

	var suggestions []WAFRuleSuggestion
	for _, c := range candidates {
		if globalSet[c.RuleID] || exceptionSet[ruleKey{c.ServiceName, c.RuleID}] {
			continue
		}
		suggestions = append(suggestions, c)
	}
	return suggestions, nil
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
	rows, err := db.query(
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
	URL             string
	Secret          string // sent as X-WAF-Secret header value
	Enabled         bool
	Events          string // comma-separated event categories: "blocked", "challenged"
	DestinationType string // "generic" (default, unchanged JSON body), "slack" (Block Kit), "discord" (embeds)
}

// webhookDestinationTypes is the allowed set for WebhookConfig.DestinationType.
// Anything else (empty, typo, a value from a future version rolled back) is
// normalized to "generic" — the original unformatted-JSON behavior — rather
// than silently failing to deliver.
var webhookDestinationTypes = map[string]bool{
	"generic": true,
	"slack":   true,
	"discord": true,
}

func (db *DB) GetWebhookConfig() (WebhookConfig, error) {
	var cfg WebhookConfig
	var enabled int
	err := db.queryRow(
		`SELECT url, secret, enabled, events, destination_type FROM webhook_config WHERE id = 1`,
	).Scan(&cfg.URL, &cfg.Secret, &enabled, &cfg.Events, &cfg.DestinationType)
	if err != nil {
		return WebhookConfig{}, err
	}
	cfg.Enabled = enabled == 1
	if !webhookDestinationTypes[cfg.DestinationType] {
		cfg.DestinationType = "generic"
	}
	if cfg.Secret, err = db.openSecret(cfg.Secret); err != nil {
		return WebhookConfig{}, fmt.Errorf("webhook secret: %w", err)
	}
	return cfg, nil
}

func (db *DB) SetWebhookConfig(cfg WebhookConfig) error {
	sealed, err := db.sealSecret(cfg.Secret)
	if err != nil {
		return err
	}
	if !webhookDestinationTypes[cfg.DestinationType] {
		cfg.DestinationType = "generic"
	}
	_, err = db.exec(
		`UPDATE webhook_config SET url=?, secret=?, enabled=?, events=?, destination_type=? WHERE id=1`,
		cfg.URL, sealed, boolToInt(cfg.Enabled), cfg.Events, cfg.DestinationType,
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
	if cfg.Token, err = db.getSecretMeta("email_token"); err != nil {
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
		"email_to":      cfg.To,
	} {
		if err := db.setMeta(key, val); err != nil {
			return err
		}
	}
	return db.setSecretMeta("email_token", cfg.Token)
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
	err := db.queryRow(`
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 403 THEN 1 ELSE 0 END), 0),
		       COUNT(DISTINCT CASE WHEN blocked = 1 THEN real_ip END),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND rule_id > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND action LIKE 'ip_blocked%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND action LIKE 'geo_blocked%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN blocked = 1 AND action LIKE 'rate_limited%' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action LIKE 'bot_challenge%' THEN 1 ELSE 0 END), 0)
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
	rows, err := db.query(query, args...)
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

// ── Threat score ──────────────────────────────────────────────────────────────
//
// Unified per-IP threat-intelligence score (issue #12) — a composite read
// model combining autoban history, bot score, ASN/hosting classification,
// geo risk, and JA4 repeat-offender history. Computed incrementally by
// internal/security/threatscore.Scorer.Record, registered via
// SetThreatScoreFn like every other log-worker fan-out hook. Distinct from
// the unrelated internal/security/threatintel package (external IP
// block-list sync) despite the similar name.

// IPThreatScore is one row in ip_threat_scores: the latest composite score
// for an IP plus the per-signal breakdown that produced it, so the admin UI
// can show *why* an IP scored what it did, not just the total.
type IPThreatScore struct {
	IP           string
	Total        int
	AutobanScore int
	BotScore     int
	ASNScore     int
	GeoScore     int
	JA4Score     int
	UpdatedAt    time.Time
}

// UpsertIPThreatScore stores s's latest composite score, replacing any
// previous score for the same IP.
func (db *DB) UpsertIPThreatScore(s IPThreatScore) error {
	cols := []string{"ip", "total_score", "autoban_score", "bot_score", "asn_score", "geo_score", "ja4_score", "updated_at"}
	updateCols := []string{"total_score", "autoban_score", "bot_score", "asn_score", "geo_score", "ja4_score", "updated_at"}
	_, err := db.exec(
		db.dialect.upsertUpdate("ip_threat_scores", cols, "?, ?, ?, ?, ?, ?, ?, ?", []string{"ip"}, updateCols),
		s.IP, s.Total, s.AutobanScore, s.BotScore, s.ASNScore, s.GeoScore, s.JA4Score, s.UpdatedAt.UTC(),
	)
	return err
}

// GetIPThreatScore returns ip's latest composite score. The second return
// value is false if no score has been recorded for ip yet.
func (db *DB) GetIPThreatScore(ip string) (IPThreatScore, bool, error) {
	var s IPThreatScore
	s.IP = ip
	err := db.queryRow(
		`SELECT total_score, autoban_score, bot_score, asn_score, geo_score, ja4_score, updated_at
		 FROM ip_threat_scores WHERE ip = ?`, ip,
	).Scan(&s.Total, &s.AutobanScore, &s.BotScore, &s.ASNScore, &s.GeoScore, &s.JA4Score, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return IPThreatScore{}, false, nil
	}
	if err != nil {
		return IPThreatScore{}, false, err
	}
	return s, true, nil
}

// GetIPThreatScores returns the total score for every IP in ips that has
// one on record, keyed by IP. IPs with no recorded score are simply absent
// from the result rather than reported as zero. A single bulk query, used by
// the IP Rules page to avoid an N+1 lookup per row.
func (db *DB) GetIPThreatScores(ips []string) (map[string]int, error) {
	out := make(map[string]int, len(ips))
	if len(ips) == 0 {
		return out, nil
	}

	placeholders := strings.Repeat("?,", len(ips))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}

	rows, err := db.query(
		`SELECT ip, total_score FROM ip_threat_scores WHERE ip IN (`+placeholders+`)`, args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var score int
		if err := rows.Scan(&ip, &score); err != nil {
			return nil, err
		}
		out[ip] = score
	}
	return out, rows.Err()
}

// BumpJA4Reputation records one observed request for ja4 (a hit, and a
// blocked hit if blocked is true) and returns the fingerprint's updated
// lifetime totals. Used to track JA4 fingerprints that keep showing up on
// blocked traffic across many IPs/connections — the ja4 package's own store
// is connection-scoped and forgets fingerprints as soon as the connection
// closes.
// bumpJA4ReputationSQL returns the dialect-specific "INSERT ... increment on
// conflict" statement for BumpJA4Reputation. Unlike every other upsert in
// this file (a plain "replace with the newly-inserted value", handled
// generically by dialect.upsertUpdate), this one increments the *existing*
// row's columns — which needs a different clause per dialect: MySQL's
// "ON DUPLICATE KEY UPDATE" allows a bare "hits = hits + 1" (unqualified
// column names there refer to the existing row; VALUES(col) refers to the
// proposed one), and so does SQLite's "ON CONFLICT DO UPDATE SET". Postgres
// alone requires the existing-row reference to be qualified with the table
// name — "hits = hits + 1" is rejected as "ambiguous" (confirmed
// empirically against a live Postgres instance, not assumed), needing
// "hits = ja4_reputation.hits + 1" instead.
func bumpJA4ReputationSQL(d dialect) string {
	switch d.name {
	case "mysql":
		return `INSERT INTO ja4_reputation (ja4, hits, blocked_hits, last_seen) VALUES (?, 1, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   hits = hits + 1,
		   blocked_hits = blocked_hits + ?,
		   last_seen = VALUES(last_seen)`
	case "postgres":
		return `INSERT INTO ja4_reputation (ja4, hits, blocked_hits, last_seen) VALUES (?, 1, ?, ?)
		 ON CONFLICT(ja4) DO UPDATE SET
		   hits = ja4_reputation.hits + 1,
		   blocked_hits = ja4_reputation.blocked_hits + ?,
		   last_seen = excluded.last_seen`
	default:
		return `INSERT INTO ja4_reputation (ja4, hits, blocked_hits, last_seen) VALUES (?, 1, ?, ?)
		 ON CONFLICT(ja4) DO UPDATE SET
		   hits = hits + 1,
		   blocked_hits = blocked_hits + ?,
		   last_seen = excluded.last_seen`
	}
}

func (db *DB) BumpJA4Reputation(ja4 string, blocked bool) (hits, blockedHits int, err error) {
	blockedInc := 0
	if blocked {
		blockedInc = 1
	}
	_, err = db.exec(
		bumpJA4ReputationSQL(db.dialect),
		ja4, blockedInc, time.Now().UTC(), blockedInc,
	)
	if err != nil {
		return 0, 0, err
	}
	err = db.queryRow(
		`SELECT hits, blocked_hits FROM ja4_reputation WHERE ja4 = ?`, ja4,
	).Scan(&hits, &blockedHits)
	return hits, blockedHits, err
}

// TypeSafeCall is one row in typesafe_calls: a single Jev API call made by
// the ASN/hosting classifier (threatscore/typesafeclassify.go), so an admin
// can see where TypeSafe token usage goes and why. Note that classifyASN
// retries a judgment on every request from an ASN whose last call errored
// (see its comment — only a successful judgment is cached), so a bad API
// key or a rate limit shows up here as repeated calls for the same ASN
// rather than the intended one-call-ever-per-ASN.
type TypeSafeCall struct {
	Ts           time.Time
	ASN          uint
	Org          string
	Hosting      bool
	InputTokens  int
	OutputTokens int
	DurationMs   int64
	Error        string
}

// typesafeCallsKeep bounds typesafe_calls the same way ratelimit/threatscore
// bound their in-memory maps — this one's on disk, so InsertTypeSafeCall
// prunes down to the newest N rows on every insert rather than relying on a
// scheduled job, since a misbehaving ASN can otherwise grow this table once
// per request instead of once per ASN.
const typesafeCallsKeep = 2000

// InsertTypeSafeCall records one Jev API call and prunes typesafe_calls back
// down to its newest typesafeCallsKeep rows.
func (db *DB) InsertTypeSafeCall(c TypeSafeCall) error {
	_, err := db.exec(
		`INSERT INTO typesafe_calls (ts, asn, org, hosting, input_tokens, output_tokens, duration_ms, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Ts.UTC(), c.ASN, c.Org, boolToInt(c.Hosting), c.InputTokens, c.OutputTokens, c.DurationMs, c.Error,
	)
	if err != nil {
		return err
	}
	var cutoff int64
	err = db.queryRow(`SELECT id FROM typesafe_calls ORDER BY id DESC LIMIT 1 OFFSET ?`, typesafeCallsKeep).Scan(&cutoff)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = db.exec(`DELETE FROM typesafe_calls WHERE id <= ?`, cutoff)
	return err
}

// ListTypeSafeCalls returns the most recent Jev API calls, newest first.
func (db *DB) ListTypeSafeCalls(limit int) ([]TypeSafeCall, error) {
	rows, err := db.query(
		`SELECT ts, asn, org, hosting, input_tokens, output_tokens, duration_ms, error
		 FROM typesafe_calls ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TypeSafeCall
	for rows.Next() {
		var c TypeSafeCall
		var hosting int
		if err := rows.Scan(&c.Ts, &c.ASN, &c.Org, &hosting, &c.InputTokens, &c.OutputTokens, &c.DurationMs, &c.Error); err != nil {
			return nil, err
		}
		c.Hosting = hosting != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// TypeSafeUsage summarizes typesafe_calls since a cutoff — the "how many
// calls, how many tokens" header on the AI Usage page.
type TypeSafeUsage struct {
	Calls        int
	Errors       int
	InputTokens  int
	OutputTokens int
}

// TypeSafeUsageSince aggregates typesafe_calls with ts >= since. Plain
// comparison, not a SQL date function — see the SQLite date/time gotcha
// this codebase documents for the requests table's ts column.
func (db *DB) TypeSafeUsageSince(since time.Time) (TypeSafeUsage, error) {
	var u TypeSafeUsage
	err := db.queryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN error <> '' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0)
		 FROM typesafe_calls WHERE ts >= ?`, since.UTC(),
	).Scan(&u.Calls, &u.Errors, &u.InputTokens, &u.OutputTokens)
	return u, err
}
