package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
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
	JA3Hash     string // JA3 TLS fingerprint MD5 hex; empty for plain HTTP
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
			if db.broadcastFn != nil {
				entry.ID = int(id)
				db.broadcastFn(entry)
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
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN country TEXT NOT NULL DEFAULT ''`)         //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN proxy_ip TEXT NOT NULL DEFAULT ''`)           //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN headers_json TEXT NOT NULL DEFAULT ''`)       //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN request_id TEXT NOT NULL DEFAULT ''`)         //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN proto TEXT NOT NULL DEFAULT ''`)              //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN tls_version TEXT NOT NULL DEFAULT ''`)        //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN tls_cipher TEXT NOT NULL DEFAULT ''`)         //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN tls_sni TEXT NOT NULL DEFAULT ''`)            //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN asn_num INTEGER NOT NULL DEFAULT 0`)          //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN org TEXT NOT NULL DEFAULT ''`)                //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN query TEXT NOT NULL DEFAULT ''`)              //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN ja3_hash TEXT NOT NULL DEFAULT ''`)           //nolint
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN bot_score INTEGER NOT NULL DEFAULT 0`)        //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_mode TEXT NOT NULL DEFAULT 'none'`)          //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_cert_path TEXT NOT NULL DEFAULT ''`)         //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_key_path TEXT NOT NULL DEFAULT ''`)          //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_expires_at TEXT NOT NULL DEFAULT ''`)        //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN rate_limit_rps REAL NOT NULL DEFAULT 0`)         //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN rate_limit_burst INTEGER NOT NULL DEFAULT 0`)    //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN bot_mode TEXT NOT NULL DEFAULT 'inherit'`)       //nolint

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
		bot_mode         TEXT NOT NULL DEFAULT 'inherit'
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
	CreatedAt time.Time
}

func (db *DB) AddIPRule(appName, ip, ruleType string) error {
	_, err := db.conn.Exec(
		`INSERT INTO ip_rules (app_name, ip, rule_type) VALUES (?, ?, ?)
		 ON CONFLICT(app_name, ip) DO UPDATE SET rule_type = excluded.rule_type`,
		appName, ip, ruleType,
	)
	return err
}

func (db *DB) RemoveIPRule(id int) error {
	_, err := db.conn.Exec(`DELETE FROM ip_rules WHERE id = ?`, id)
	return err
}

func (db *DB) ListIPRules() ([]IPRule, error) {
	rows, err := db.conn.Query(
		`SELECT id, app_name, ip, rule_type, created_at FROM ip_rules ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []IPRule
	for rows.Next() {
		var r IPRule
		if err := rows.Scan(&r.ID, &r.AppName, &r.IP, &r.RuleType, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
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
	ID             int
	Name           string
	Host           string
	Prefix         string
	Backend        string
	CreatedAt      time.Time
	TLSMode        string
	TLSCertPath    string
	TLSKeyPath     string
	TLSExpiresAt   string
	RateLimitRPS   float64
	RateLimitBurst int
	BotMode        string // "inherit" | "always" | "off"
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

// ClearServiceTLS reverts a service to plain HTTP (no TLS).
func (db *DB) ClearServiceTLS(id int) error {
	return db.SetServiceTLS(id, "none", "", "", "")
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
		`SELECT id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at, rate_limit_rps, rate_limit_burst, bot_mode FROM services ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		var s Service
		if err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt, &s.RateLimitRPS, &s.RateLimitBurst, &s.BotMode); err != nil {
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
		`SELECT id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at, rate_limit_rps, rate_limit_burst, bot_mode FROM services WHERE id = ?`,
		id,
	).Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt, &s.RateLimitRPS, &s.RateLimitBurst, &s.BotMode)
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
			 ja3_hash, bot_score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
		       ja3_hash, bot_score
		FROM requests WHERE id = ?`, id).Scan(
		&d.ID, &d.Timestamp, &d.AppName, &d.RealIP, &d.ProxyIP, &d.Country,
		&d.Method, &d.Host, &d.Path, &d.Query,
		&d.Status, &blocked, &d.RuleID, &d.Action, &d.UserAgent, &d.Duration,
		&d.HeadersJSON, &d.RequestID, &d.Proto, &d.TLSVersion, &d.TLSCipher,
		&d.TLSSNI, &d.ASN, &d.Org, &d.JA3Hash, &d.BotScore,
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

// SeedTestAdmin creates a default admin account (admin@localhost / admin123)
// if no admin credentials exist in the DB yet. Called once on startup during
// development; production installs replace this via the install script.
func (db *DB) SeedTestAdmin() error {
	email, _ := db.getMeta("admin_email")
	if email != "" {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}
	if err := db.setMeta("admin_email", "admin@localhost"); err != nil {
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

// CreateSession generates a random token, stores it, and returns it for use
// as a session cookie value.
func (db *DB) CreateSession() (string, error) {
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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
