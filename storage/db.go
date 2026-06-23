package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
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
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Single writer is fine; WAL mode keeps readers non-blocking.
	if _, err := conn.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		return nil, err
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	// Idempotent column migration for existing databases.
	db.conn.Exec(`ALTER TABLE requests ADD COLUMN country TEXT NOT NULL DEFAULT ''`) //nolint

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
	CREATE INDEX IF NOT EXISTS idx_requests_ts      ON requests(ts);
	CREATE INDEX IF NOT EXISTS idx_requests_ip      ON requests(real_ip);
	CREATE INDEX IF NOT EXISTS idx_requests_blocked ON requests(blocked);
	CREATE INDEX IF NOT EXISTS idx_requests_app     ON requests(app_name);

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
	`)
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

func (db *DB) GetStats() (Stats, error) {
	var s Stats
	today := time.Now().UTC().Format("2006-01-02")

	row := db.conn.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE date(ts) = ?),
			COUNT(*) FILTER (WHERE date(ts) = ? AND blocked = 1),
			COUNT(*),
			COUNT(*) FILTER (WHERE blocked = 1)
		FROM requests`, today, today)

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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
