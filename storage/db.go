package storage

import (
	"database/sql"
	"fmt"
	"log"
	"time"

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
	conn     *sql.DB
	logQueue chan RequestLog
	logDone  chan struct{}
}

// RequestLog is one row in the requests table.
type RequestLog struct {
	Timestamp time.Time
	AppName   string
	RealIP    string
	Country   string // ISO 3166-1 alpha-2, e.g. "US", "CN"
	Method    string
	Host      string
	Path      string
	Status    int
	Blocked   bool
	RuleID    int
	Action    string
	UserAgent string
	Duration  int64 // milliseconds
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
		err := db.InsertRequest(entry)
		dur := time.Since(writeStart)
		if err != nil {
			log.Printf("storage: async request log write failed after %s: %v", dur, err)
		} else if dur >= slowWriteThreshold {
			log.Printf("storage: slow request log write, took %s (queue depth now %d)", dur, db.QueueDepth())
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
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN country TEXT NOT NULL DEFAULT ''`)        //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_mode TEXT NOT NULL DEFAULT 'none'`)   //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_cert_path TEXT NOT NULL DEFAULT ''`)  //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_key_path TEXT NOT NULL DEFAULT ''`)   //nolint
	db.conn.Exec(`ALTER TABLE services ADD COLUMN tls_expires_at TEXT NOT NULL DEFAULT ''`) //nolint

	_, err := db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS requests (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ts          DATETIME NOT NULL,
		app_name    TEXT NOT NULL,
		real_ip     TEXT NOT NULL,
		country     TEXT NOT NULL DEFAULT '',
		method      TEXT NOT NULL,
		host        TEXT NOT NULL,
		path        TEXT NOT NULL,
		status      INTEGER NOT NULL,
		blocked     INTEGER NOT NULL DEFAULT 0,
		rule_id     INTEGER NOT NULL DEFAULT 0,
		action      TEXT NOT NULL DEFAULT '',
		user_agent  TEXT NOT NULL DEFAULT '',
		duration_ms INTEGER NOT NULL DEFAULT 0
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
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		name           TEXT NOT NULL UNIQUE,
		host           TEXT NOT NULL DEFAULT '',
		prefix         TEXT NOT NULL DEFAULT '',
		backend        TEXT NOT NULL,
		created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		tls_mode       TEXT NOT NULL DEFAULT 'none',
		tls_cert_path  TEXT NOT NULL DEFAULT '',
		tls_key_path   TEXT NOT NULL DEFAULT '',
		tls_expires_at TEXT NOT NULL DEFAULT ''
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
	ID           int
	Name         string
	Host         string
	Prefix       string
	Backend      string
	CreatedAt    time.Time
	TLSMode      string
	TLSCertPath  string
	TLSKeyPath   string
	TLSExpiresAt string
}

func (db *DB) AddService(name, host, prefix, backend string) error {
	_, err := db.conn.Exec(
		`INSERT INTO services (name, host, prefix, backend) VALUES (?, ?, ?, ?)`,
		name, host, prefix, backend,
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

func (db *DB) ListServices() ([]Service, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at FROM services ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		var s Service
		if err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt); err != nil {
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
		`SELECT id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at FROM services WHERE id = ?`,
		id,
	).Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt)
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
		if err := db.AddService(a.Name, a.Host, a.Prefix, a.Backend); err != nil {
			return fmt.Errorf("migrate app %q: %w", a.Name, err)
		}
	}
	return db.setMeta(metaKeyServicesMigrated, "1")
}

// InsertRequest writes one request log entry.
func (db *DB) InsertRequest(r RequestLog) error {
	_, err := db.conn.Exec(`
		INSERT INTO requests
			(ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Timestamp.UTC(),
		r.AppName,
		r.RealIP,
		r.Country,
		r.Method,
		r.Host,
		r.Path,
		r.Status,
		boolToInt(r.Blocked),
		r.RuleID,
		r.Action,
		r.UserAgent,
		r.Duration,
	)
	return err
}

// --- Query helpers (used by dashboard later) ---

type Stats struct {
	TotalToday   int
	BlockedToday int
	TotalAll     int
	BlockedAll   int
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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
