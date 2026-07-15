package storage

import (
	"fmt"
	"regexp"
)

// mysqlTextDefault matches a quoted-string DEFAULT clause, e.g.
// "DEFAULT ”" or "DEFAULT 'inherit'". Every DEFAULT in this schema on a
// quoted string literal is on a TEXT column (INTEGER/REAL columns here only
// ever default to bare numbers), so this is safe to apply blanket rather
// than needing to track column types — see the comment on
// mysqlWrapTextDefaults for why it's needed at all.
var mysqlTextDefault = regexp.MustCompile(`DEFAULT '([^']*)'`)

// mysqlWrapTextDefaults rewrites quoted-string DEFAULT clauses into MySQL's
// parenthesized-expression-default form. MySQL rejects a plain
// "TEXT ... DEFAULT ”" outright ("BLOB, TEXT, GEOMETRY or JSON column
// can't have a default value") — confirmed empirically against mysql:8,
// not assumed — unless the default is written as an expression, which
// MySQL 8.0.13+ accepts if the literal is wrapped in parentheses:
// "DEFAULT (”)". SQLite and Postgres both accept a plain quoted-string
// default on a TEXT column natively and never need this rewrite.
func mysqlWrapTextDefaults(stmt string) string {
	return mysqlTextDefault.ReplaceAllString(stmt, "DEFAULT ('$1')")
}

// schemaStatements returns the ordered list of DDL statements that create
// every table and index this application needs, rendered for db.dialect.
// Each entry is executed as its own Exec call rather than one big
// multi-statement string (the original single-Exec form this replaced):
// only SQLite's driver executes several semicolon-separated statements in
// one Exec call by default. MySQL requires the DSN param
// multiStatements=true, and pgx's default extended-protocol query path
// rejects a string containing more than one command outright — one
// statement per Exec call works identically on all three without relying on
// any driver-specific opt-in.
func (db *DB) schemaStatements() []string {
	d := db.dialect
	pk := d.autoIncrementPK()
	ts := d.timestampType()

	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS requests (
			id           %s,
			ts           %s NOT NULL,
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
		)`, pk, ts),
		d.createIndexIfNotExists("idx_requests_ts", "requests", "ts"),
		d.createIndexOnText("idx_requests_ip", "requests", "real_ip", 45),
		d.createIndexIfNotExists("idx_requests_blocked", "requests", "blocked"),
		d.createIndexOnText("idx_requests_app", "requests", "app_name", 191),
		d.createIndexIfNotExists("idx_requests_blocked_ts", "requests", "blocked, ts"),

		// app_name/ip/country_code are VARCHAR rather than TEXT here (and in
		// every other table below with a PRIMARY KEY or UNIQUE constraint on
		// a string column): MySQL cannot use a TEXT/BLOB column as a primary
		// key or in a UNIQUE constraint at all — confirmed empirically
		// against mysql:8 ("BLOB/TEXT column ... used in key specification
		// without a key length") — while VARCHAR(n), having an inherent
		// bounded length, works natively for this on all three dialects
		// (SQLite ignores the length like it does every declared type;
		// Postgres enforces it, same as it would for TEXT). Lengths are
		// sized generously for their real content (45 covers the longest
		// possible IPv6 literal, 255 is a conventional generic-identifier
		// bound) rather than tightly, since unlike MySQL's index-only
		// prefix-length trick (see createIndexOnText), this bound is a real
		// storage constraint enforced on every insert.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS ip_rules (
			id         %s,
			app_name   VARCHAR(255) NOT NULL DEFAULT '',
			ip         VARCHAR(45) NOT NULL,
			rule_type  TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
			note       TEXT NOT NULL DEFAULT '',
			created_at %s NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(app_name, ip)
		)`, pk, ts),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS geo_rules (
			id           %s,
			app_name     VARCHAR(255) NOT NULL DEFAULT '',
			country_code VARCHAR(8) NOT NULL,
			rule_type    TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
			created_at   %s NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(app_name, country_code)
		)`, pk, ts),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS meta (
			%s VARCHAR(255) PRIMARY KEY,
			value TEXT NOT NULL
		)`, d.quoteIdent("key")),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS services (
			id               %s,
			name             VARCHAR(255) NOT NULL UNIQUE,
			host             TEXT NOT NULL DEFAULT '',
			prefix           TEXT NOT NULL DEFAULT '',
			backend          TEXT NOT NULL,
			created_at       %s NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
			session_cookie_name TEXT NOT NULL DEFAULT '',
			cache_ttl_floor    INTEGER NOT NULL DEFAULT 0,
			cache_ttl_ceiling  INTEGER NOT NULL DEFAULT 0,
			cache_grace        INTEGER NOT NULL DEFAULT 0,
			cache_keep         INTEGER NOT NULL DEFAULT 0
		)`, pk, ts),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS certificates (
			id          %s,
			name        VARCHAR(255) NOT NULL UNIQUE,
			domains     TEXT     NOT NULL DEFAULT '',
			expires_at  TEXT     NOT NULL DEFAULT '',
			cert_path   TEXT     NOT NULL DEFAULT '',
			key_path    TEXT     NOT NULL DEFAULT '',
			created_at  %s NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`, pk, ts),

		// token is 32 random bytes hex-encoded (64 chars, see
		// DB.CreateSession) — VARCHAR(64) fits exactly.
		`CREATE TABLE IF NOT EXISTS sessions (
			token      VARCHAR(64) PRIMARY KEY,
			created_at TEXT NOT NULL
		)`,

		// key_hash is a SHA-256 hex digest (64 chars, see ui.CreateAPIKey).
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS api_keys (
			id           %s,
			name         TEXT NOT NULL,
			key_prefix   TEXT NOT NULL,
			key_hash     VARCHAR(64) NOT NULL UNIQUE,
			created_at   %s NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at %s
		)`, pk, ts, ts),

		`CREATE TABLE IF NOT EXISTS rate_state (
			ip          VARCHAR(45) PRIMARY KEY,
			tokens      REAL NOT NULL,
			last_refill TEXT NOT NULL
		)`,

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS waf_disabled_rules (
			id         %s,
			rule_id    INTEGER NOT NULL UNIQUE,
			reason     TEXT NOT NULL DEFAULT '',
			created_at %s NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`, pk, ts),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS waf_service_rule_exceptions (
			id           %s,
			service_name VARCHAR(255) NOT NULL,
			rule_id      INTEGER NOT NULL,
			reason       TEXT NOT NULL DEFAULT '',
			created_at   %s NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(service_name, rule_id)
		)`, pk, ts),

		// url is VARCHAR(768) rather than the 255 used for other identifier
		// columns above: 768 chars * 4 bytes (utf8mb4) = 3072 bytes, MySQL's
		// InnoDB max index key length with the default DYNAMIC row format —
		// the largest a UNIQUE VARCHAR column can be there at all, needed
		// headroom since a real block-list URL can be long.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS threat_intel_sources (
			id             %s,
			label          TEXT NOT NULL,
			url            VARCHAR(768) NOT NULL UNIQUE,
			interval_hours INTEGER NOT NULL DEFAULT 24,
			enabled        INTEGER NOT NULL DEFAULT 1,
			last_synced_at TEXT NOT NULL DEFAULT '',
			last_error     TEXT NOT NULL DEFAULT '',
			ip_count       INTEGER NOT NULL DEFAULT 0,
			created_at     %s NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`, pk, ts),

		`CREATE TABLE IF NOT EXISTS threat_intel_ips (
			source_id INTEGER NOT NULL,
			ip        VARCHAR(45) NOT NULL,
			PRIMARY KEY (source_id, ip)
		)`,

		`CREATE TABLE IF NOT EXISTS webhook_config (
			id               INTEGER PRIMARY KEY CHECK (id = 1),
			url              TEXT    NOT NULL DEFAULT '',
			secret           TEXT    NOT NULL DEFAULT '',
			enabled          INTEGER NOT NULL DEFAULT 0,
			events           TEXT    NOT NULL DEFAULT 'blocked,challenged',
			destination_type TEXT    NOT NULL DEFAULT 'generic'
		)`,
		d.upsertIgnore("webhook_config", []string{"id"}, "1", []string{"id"}),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS ip_threat_scores (
			ip            VARCHAR(45) PRIMARY KEY,
			total_score   INTEGER NOT NULL DEFAULT 0,
			autoban_score INTEGER NOT NULL DEFAULT 0,
			bot_score     INTEGER NOT NULL DEFAULT 0,
			asn_score     INTEGER NOT NULL DEFAULT 0,
			geo_score     INTEGER NOT NULL DEFAULT 0,
			ja4_score     INTEGER NOT NULL DEFAULT 0,
			updated_at    %s NOT NULL
		)`, ts),

		// ja4 fingerprints are a fixed ~36-char format (see ja4.Compute);
		// VARCHAR(64) leaves headroom without needing to track the exact
		// spec length here.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS ja4_reputation (
			ja4          VARCHAR(64) PRIMARY KEY,
			hits         INTEGER NOT NULL DEFAULT 0,
			blocked_hits INTEGER NOT NULL DEFAULT 0,
			last_seen    %s NOT NULL
		)`, ts),
	}

	if d.name == "mysql" {
		for i, stmt := range stmts {
			stmts[i] = mysqlWrapTextDefaults(stmt)
		}
	}
	return stmts
}
