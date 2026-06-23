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
	_, err := db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS requests (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		ts         DATETIME NOT NULL,
		app_name   TEXT NOT NULL,
		real_ip    TEXT NOT NULL,
		method     TEXT NOT NULL,
		host       TEXT NOT NULL,
		path       TEXT NOT NULL,
		status     INTEGER NOT NULL,
		blocked    INTEGER NOT NULL DEFAULT 0,
		rule_id    INTEGER NOT NULL DEFAULT 0,
		action     TEXT NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		duration_ms INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_requests_ts      ON requests(ts);
	CREATE INDEX IF NOT EXISTS idx_requests_ip      ON requests(real_ip);
	CREATE INDEX IF NOT EXISTS idx_requests_blocked ON requests(blocked);
	CREATE INDEX IF NOT EXISTS idx_requests_app     ON requests(app_name);
	`)
	return err
}

// InsertRequest writes one request log entry.
func (db *DB) InsertRequest(r RequestLog) error {
	_, err := db.conn.Exec(`
		INSERT INTO requests
			(ts, app_name, real_ip, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Timestamp.UTC(),
		r.AppName,
		r.RealIP,
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
	query := `SELECT id, ts, app_name, real_ip, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms
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
			&row.ID, &row.Timestamp, &row.AppName, &row.RealIP,
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
