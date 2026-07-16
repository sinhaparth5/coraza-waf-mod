package storage

import (
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// dialect captures the handful of SQL differences between the backends this
// package supports, so the ~130 query methods elsewhere in db.go can stay
// written once (mostly against "?" placeholders and shared DDL/upsert
// helpers) instead of forking per-driver at every call site. sqlx.Rebind
// handles placeholder translation ("?" -> "$1, $2, ...") transparently, so
// this type only needs to cover what Rebind can't: DDL column types and
// upsert-clause syntax, which differ enough between SQLite/MySQL/Postgres
// that they have to be generated per dialect.
type dialect struct {
	// name identifies the dialect for logging/diagnostics and is one of
	// "sqlite" (default), "mysql" (also covers MariaDB, wire-compatible),
	// or "postgres" (also covers CockroachDB and Neon, both Postgres-wire-
	// protocol-compatible).
	name string

	// driverName is the database/sql driver registered name passed to
	// sqlx.Open.
	driverName string
}

var (
	dialectSQLite   = dialect{name: "sqlite", driverName: "sqlite"}
	dialectMySQL    = dialect{name: "mysql", driverName: "mysql"}
	dialectPostgres = dialect{name: "postgres", driverName: "pgx"}
)

// resolveDialect maps a --db-driver flag value to its dialect. driverName is
// normalized to lowercase and "mariadb" is accepted as a synonym for "mysql"
// since MariaDB is wire-compatible and uses the same Go driver — there is no
// separate MariaDB dialect.
func resolveDialect(driverName string) (dialect, error) {
	switch strings.ToLower(strings.TrimSpace(driverName)) {
	case "", "sqlite":
		return dialectSQLite, nil
	case "mysql", "mariadb":
		return dialectMySQL, nil
	case "postgres", "postgresql", "cockroachdb", "cockroach", "neon":
		return dialectPostgres, nil
	default:
		return dialect{}, fmt.Errorf("unknown db driver %q (expected sqlite, mysql, mariadb, or postgres)", driverName)
	}
}

// autoIncrementPK returns the column-type fragment used in CREATE TABLE
// statements for an integer primary key that auto-increments, substituted
// for SQLite's "INTEGER PRIMARY KEY AUTOINCREMENT" syntax.
func (d dialect) autoIncrementPK() string {
	switch d.name {
	case "mysql":
		return "INTEGER PRIMARY KEY AUTO_INCREMENT"
	case "postgres":
		return "INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
	default:
		return "INTEGER PRIMARY KEY AUTOINCREMENT"
	}
}

// addColumnIfNotExists returns an "ALTER TABLE ... ADD COLUMN ..." statement
// for this dialect. MySQL (8.0.29+) and Postgres both support
// "ADD COLUMN IF NOT EXISTS" natively; SQLite has no such syntax at all,
// confirmed empirically against a recent bundled build (3.53.2) rather than
// assumed from version history — its ALTER TABLE grammar has never gained
// an IF NOT EXISTS clause for ADD COLUMN. Its statement omits "IF NOT
// EXISTS" and relies on the caller ignoring the resulting "duplicate
// column" error instead — the existing //nolint-annotated db.conn.Exec(...)
// call sites already do this.
func (d dialect) addColumnIfNotExists(table, columnDef string) string {
	switch d.name {
	case "mysql", "postgres":
		return fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s", table, columnDef)
	default:
		return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", table, columnDef)
	}
}

// quoteIdent quotes an identifier that collides with a reserved word, so it
// can still be used as a column name. The only such identifier in this
// schema is the meta table's "key" column — a reserved word in MySQL
// (confirmed empirically: "You have an error in your SQL syntax ... near
// 'VARCHAR(255) PRIMARY KEY'"), needing backtick-quoting there. SQLite and
// Postgres both accept "key" as a bare column name and need no quoting.
func (d dialect) quoteIdent(name string) string {
	if d.name == "mysql" {
		return "`" + name + "`"
	}
	return name
}

// timestampType returns the column-type fragment used for a
// created_at/updated_at/last_seen-style column, substituted for SQLite's
// "DATETIME" (SQLite has no real date/time type — DATETIME is dynamically
// typed like everything else — and MySQL accepts DATETIME natively too, so
// both keep the same fragment; Postgres has no DATETIME type at all and
// requires TIMESTAMP).
func (d dialect) timestampType() string {
	if d.name == "postgres" {
		return "TIMESTAMP"
	}
	return "DATETIME"
}

// createIndexIfNotExists returns a "CREATE INDEX ..." statement for this
// dialect. SQLite and Postgres both support "IF NOT EXISTS" on CREATE
// INDEX; MySQL's grammar has no such clause at all (unlike its ALTER TABLE
// ADD COLUMN, which does support IF NOT EXISTS as of 8.0.29) — its
// statement omits the clause and relies on the caller ignoring the
// resulting "duplicate key name" error on a rerun, the same swallow-the-
// error convention addColumnIfNotExists uses for SQLite.
func (d dialect) createIndexIfNotExists(name, table, columns string) string {
	if d.name == "mysql" {
		return fmt.Sprintf("CREATE INDEX %s ON %s(%s)", name, table, columns)
	}
	return fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", name, table, columns)
}

// createIndexOnText is createIndexIfNotExists for a single TEXT column,
// adding a MySQL-required key-length prefix. MySQL cannot index a full
// TEXT/BLOB column without one — confirmed empirically against mysql:8
// ("BLOB/TEXT column 'real_ip' used in key specification without a key
// length"), not assumed — while SQLite and Postgres both index a full TEXT
// column natively and need no such prefix. mysqlPrefixLen only matters for
// MySQL; pick it long enough to cover every real value (e.g. 45 for an IPv6
// address column) since MySQL only indexes — and can only enforce
// uniqueness over — that many leading bytes.
func (d dialect) createIndexOnText(name, table, column string, mysqlPrefixLen int) string {
	if d.name == "mysql" {
		return fmt.Sprintf("CREATE INDEX %s ON %s(%s(%d))", name, table, column, mysqlPrefixLen)
	}
	return fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", name, table, column)
}

// upsertIgnore returns a complete "INSERT ... " statement that silently
// does nothing if a row conflicting on conflictCols already exists.
// placeholders is the already-sized "?, ?, ..." (or literal values, for the
// no-args schema-seed call sites) placeholder/value list matching cols.
// SQLite and Postgres share "INSERT INTO t (...) VALUES (...)
// ON CONFLICT(...) DO NOTHING"; MySQL has no ON CONFLICT clause at all, so
// its equivalent moves the "ignore violations" behavior in front of the
// column list instead: "INSERT IGNORE INTO t (...) VALUES (...)" (MySQL's
// IGNORE applies to the whole statement, not a specific conflict target,
// but every call site here only has one unique/primary-key column set to
// conflict on anyway, so the behavior is equivalent in practice).
func (d dialect) upsertIgnore(table string, cols []string, placeholders string, conflictCols []string) string {
	colList := strings.Join(cols, ", ")
	if d.name == "mysql" {
		return fmt.Sprintf("INSERT IGNORE INTO %s (%s) VALUES (%s)", table, colList, placeholders)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO NOTHING",
		table, colList, placeholders, strings.Join(conflictCols, ", "))
}

// upsertUpdate returns a complete "INSERT ... " statement that overwrites
// updateCols with the newly-inserted values when a row conflicting on
// conflictCols already exists. SQLite and Postgres share "INSERT INTO t
// (...) VALUES (...) ON CONFLICT(...) DO UPDATE SET col = excluded.col,
// ..."; MySQL's equivalent is "ON DUPLICATE KEY UPDATE col = VALUES(col),
// ..." — the VALUES(col) form (rather than MySQL 8.0.19's newer row-alias
// syntax) is used for compatibility with older MySQL 8.0.x point releases.
func (d dialect) upsertUpdate(table string, cols []string, placeholders string, conflictCols, updateCols []string) string {
	colList := strings.Join(cols, ", ")
	if d.name == "mysql" {
		sets := make([]string, len(updateCols))
		for i, c := range updateCols {
			sets[i] = fmt.Sprintf("%s = VALUES(%s)", c, c)
		}
		return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s",
			table, colList, placeholders, strings.Join(sets, ", "))
	}
	sets := make([]string, len(updateCols))
	for i, c := range updateCols {
		sets[i] = fmt.Sprintf("%s = excluded.%s", c, c)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		table, colList, placeholders, strings.Join(conflictCols, ", "), strings.Join(sets, ", "))
}

// openDB opens a database handle for this dialect and applies
// dialect-appropriate connection tuning. For SQLite, tuning is passed via
// DSN "_pragma" params (see the comment on the historical sqlite-only Open
// for why this must be DSN-level, not a post-open Exec). For MySQL/Postgres,
// there is no PRAGMA equivalent — tuning is standard connection-pool sizing
// via SetMaxOpenConns/SetMaxIdleConns/SetConnMaxLifetime instead, since both
// servers handle their own concurrent-writer arbitration server-side rather
// than requiring a client-side busy_timeout retry loop the way SQLite does.
func (d dialect) openDB(dsn string) (*sqlx.DB, error) {
	switch d.name {
	case "sqlite":
		fullDSN := dsn + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
		conn, err := sqlx.Open(d.driverName, fullDSN)
		if err != nil {
			return nil, err
		}
		// SQLite still only allows one writer at a time regardless of pool
		// size, but WAL mode lets multiple readers proceed concurrently
		// with that one writer — so a small pool (rather than 1) lets
		// reads (dashboard, logs page) avoid queuing behind writes
		// (request logging).
		conn.SetMaxOpenConns(8)
		return conn, nil
	case "mysql":
		// go-sql-driver/mysql scans DATETIME/TIMESTAMP columns as raw
		// []byte, not time.Time, unless parseTime is enabled — confirmed
		// empirically against mysql:8 ("unsupported Scan, storing
		// driver.Value type []uint8 into type *time.Time") on every one of
		// this package's Scan(&someTime) call sites. Forced here via the
		// driver's own Config (not a string-concatenated "?parseTime=true")
		// so it applies uniformly regardless of what DSN shape a user's
		// --db flag supplies, and so it can't be silently overridden by a
		// user-supplied parseTime=false.
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			return nil, fmt.Errorf("parse mysql dsn: %w", err)
		}
		cfg.ParseTime = true
		conn, err := sqlx.Open(d.driverName, cfg.FormatDSN())
		if err != nil {
			return nil, err
		}
		conn.SetMaxOpenConns(8)
		return conn, nil
	default:
		conn, err := sqlx.Open(d.driverName, dsn)
		if err != nil {
			return nil, err
		}
		conn.SetMaxOpenConns(8)
		return conn, nil
	}
}
