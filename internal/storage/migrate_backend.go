package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// MigrationReport summarizes a MigrateConfigTo run: how many rows moved per
// table, in the order they were migrated.
type MigrationReport struct {
	Tables    []MigrationTableResult
	TotalRows int
}

// MigrationTableResult is one table's row count within a MigrationReport.
type MigrationTableResult struct {
	Table string
	Rows  int
}

// MigrateConfigTo copies this DB's *configuration* — everything that makes
// the WAF behave the same on a new backend — into a freshly-opened
// connection at targetDriver/targetDSN, and creates that connection's
// schema along the way (OpenWithDriver always runs migrate() internally, so
// there is nothing extra to do for "the tables should be created there").
//
// Migrated: services, ip_rules, geo_rules, meta (settings, secrets,
// credentials), certificates, api_keys, waf_disabled_rules,
// waf_service_rule_exceptions, threat_intel_sources + their synced
// threat_intel_ips, webhook_config, ip_threat_scores, ja4_reputation.
//
// Deliberately NOT migrated: requests (the access/request log — could be
// millions of rows on a long-running install; disposable operational
// history, not configuration, matching the existing `prune` command's own
// treatment of this table), sessions (recreated on next login), and
// rate_state (transient token-bucket runtime state that's meaningless to
// carry across a backend switch).
//
// The source (db) is never modified, written to, or closed — only ever
// read from — so the caller's existing database file/connection is left
// completely intact regardless of outcome; this is what lets the Settings
// page keep the original SQLite file as a fallback after switching.
//
// Primary key IDs are preserved verbatim on the target rather than
// re-generated, since services.cert_id and threat_intel_ips.source_id
// reference other tables' ids by value. A Postgres target additionally
// needs "OVERRIDING SYSTEM VALUE" on those inserts — confirmed empirically
// against postgres:16 that its GENERATED ALWAYS AS IDENTITY columns reject
// an explicit id value ("cannot insert a non-DEFAULT value into column
// id") without it, and that inserting explicit ids doesn't disturb the
// identity sequence for rows inserted normally afterward. MySQL's
// AUTO_INCREMENT and SQLite's AUTOINCREMENT both accept an explicit id
// with no special syntax.
//
// TIMESTAMP/DATETIME-typed columns (created_at, updated_at, last_seen, ...)
// are scanned and reinserted as typed time.Time, never as a plain string —
// confirmed empirically that MySQL's DATETIME column rejects the ISO8601
// 'T'/'Z' string format a *string scan of the same column hands back,
// while a typed time.Time round-trips correctly through every driver's own
// wire encoding on all three dialects. Columns that are plain TEXT/VARCHAR
// in the schema despite holding a timestamp-shaped value (services.
// tls_expires_at, threat_intel_sources.last_synced_at, sessions.created_at
// — the last of which isn't migrated at all) are copied as plain strings,
// which is safe for them specifically since they were never the dialect's
// native timestamp type to begin with.
//
// This is not wrapped in a single cross-database transaction: config-sized
// row counts make that extra complexity (every insert would need to go
// through a *sqlx.Tx with its own Rebind, mirroring SaveRateLimitState's
// existing pattern) disproportionate for a one-shot admin action. A
// failure partway leaves the target with whatever tables completed before
// it — the returned MigrationReport always reflects exactly how far it
// got, even on error, so the admin can see what happened; the recommended
// recovery is to point Settings at a fresh, empty target and retry rather
// than trying to resume in place.
func (db *DB) MigrateConfigTo(targetDriver, targetDSN string) (MigrationReport, error) {
	target, err := OpenWithDriver(targetDriver, targetDSN)
	if err != nil {
		return MigrationReport{}, fmt.Errorf("open target: %w", err)
	}
	defer target.Close()

	overriding := target.dialect.name == "postgres"

	steps := []struct {
		table string
		fn    func(source, target *DB, overriding bool) (int, error)
		// hasIdentitySeq marks tables with an actual auto-increment/identity
		// id column (as opposed to webhook_config's literal non-identity
		// PK, or tables with no id column at all) — see the fixup call
		// below for why this matters on a Postgres target.
		hasIdentitySeq bool
	}{
		{"meta", migrateMetaTable, false},
		{"certificates", migrateCertificatesTable, true},
		{"services", migrateServicesTable, true},
		{"ip_rules", migrateIPRulesTable, true},
		{"geo_rules", migrateGeoRulesTable, true},
		{"api_keys", migrateAPIKeysTable, true},
		{"waf_disabled_rules", migrateWAFDisabledRulesTable, true},
		{"waf_service_rule_exceptions", migrateWAFServiceExceptionsTable, true},
		{"threat_intel_sources", migrateThreatIntelSourcesTable, true},
		{"threat_intel_ips", migrateThreatIntelIPsTable, false},
		{"webhook_config", migrateWebhookConfigTable, false},
		{"ip_threat_scores", migrateIPThreatScoresTable, false},
		{"ja4_reputation", migrateJA4ReputationTable, false},
	}

	var report MigrationReport
	for _, step := range steps {
		n, err := step.fn(db, target, overriding)
		report.Tables = append(report.Tables, MigrationTableResult{Table: step.table, Rows: n})
		report.TotalRows += n
		if err != nil {
			return report, fmt.Errorf("migrate %s (after %d rows): %w", step.table, n, err)
		}
		// Postgres does not auto-advance a GENERATED ALWAYS AS IDENTITY
		// sequence for an OVERRIDING SYSTEM VALUE insert (confirmed
		// empirically — only inserts that actually draw from nextval() do)
		// — without this, the very next normal insert on the target (e.g.
		// adding a service through the admin UI after switching backends)
		// can collide with an id that was just migrated and fail with a
		// duplicate-key error. MySQL's AUTO_INCREMENT and SQLite's
		// AUTOINCREMENT both self-advance past an explicit value with no
		// equivalent fixup needed.
		if overriding && step.hasIdentitySeq && n > 0 {
			if err := fixPostgresIdentitySequence(target, step.table); err != nil {
				return report, fmt.Errorf("advance %s identity sequence: %w", step.table, err)
			}
		}
	}
	return report, nil
}

// fixPostgresIdentitySequence sets table's identity sequence to continue
// after the highest id present, so a subsequent normal (non-explicit-id)
// insert doesn't collide with a row MigrateConfigTo just wrote via
// OVERRIDING SYSTEM VALUE. Only called when at least one row was migrated
// into a table that actually has an identity column (see hasIdentitySeq).
func fixPostgresIdentitySequence(target *DB, table string) error {
	_, err := target.exec(fmt.Sprintf(
		`SELECT setval(pg_get_serial_sequence('%s', 'id'), (SELECT MAX(id) FROM %s))`, table, table,
	))
	return err
}

// overridingClause returns " OVERRIDING SYSTEM VALUE" when the target is
// Postgres and this table has an auto-increment id column — see
// MigrateConfigTo's doc comment. A no-op ("") for every other case.
func overridingClause(overriding bool) string {
	if overriding {
		return " OVERRIDING SYSTEM VALUE"
	}
	return ""
}

// placeholders returns "?, ?, ..., ?" for n items — used instead of
// hand-counting "?" per INSERT, since several tables here have 15-20+
// columns and a miscount would bind the wrong value to the wrong column
// silently (Go's database/sql has no compile-time arity check).
func placeholders(n int) string {
	ph := make([]string, n)
	for i := range ph {
		ph[i] = "?"
	}
	return strings.Join(ph, ", ")
}

func migrateMetaTable(source, target *DB, _ bool) (int, error) {
	keyCol := source.dialect.quoteIdent("key")
	rows, err := source.query(`SELECT ` + keyCol + `, value FROM meta`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	isSecret := make(map[string]bool, len(secretMetaKeys))
	for _, k := range secretMetaKeys {
		isSecret[k] = true
	}

	n := 0
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return n, err
		}
		if isSecret[key] {
			// value may be sealed under the source's own encryption key (or
			// plaintext if none configured) — decrypt via the source's own
			// state first, then let the target reseal under whatever key
			// (if any) it has. Copying the raw stored value verbatim would
			// produce an undecryptable ciphertext blob on a target with a
			// different (or absent) --db-key-file.
			plain, err := source.openSecret(value)
			if err != nil {
				return n, fmt.Errorf("decrypt %s: %w", key, err)
			}
			if err := target.setSecretMeta(key, plain); err != nil {
				return n, err
			}
		} else if err := target.setMeta(key, value); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateCertificatesTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var name, domains, expiresAt, certPath, keyPath string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &domains, &expiresAt, &certPath, &keyPath, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO certificates (id, name, domains, expires_at, cert_path, key_path, created_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(7))
		if _, err := target.exec(q, id, name, domains, expiresAt, certPath, keyPath, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateServicesTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT ` + serviceColumns + ` FROM services`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		s, err := source.scanService(rows)
		if err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO services (%s)%s VALUES (%s)`,
			serviceColumns, overridingClause(overriding), placeholders(21))
		if _, err := target.exec(q,
			s.ID, s.Name, s.Host, s.Prefix, s.Backend, s.CreatedAt, s.TLSMode, s.TLSCertPath, s.TLSKeyPath, s.TLSExpiresAt,
			s.RateLimitRPS, s.RateLimitBurst, s.BotMode, s.CertID, boolToInt(s.CacheEnabled), boolToInt(s.CacheBySession),
			s.SessionCookieName, s.CacheTTLFloor, s.CacheTTLCeiling, s.CacheGrace, s.CacheKeep,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateIPRulesTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT id, app_name, ip, rule_type, note, created_at FROM ip_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int
		var appName, ip, ruleType, note string
		var createdAt time.Time
		if err := rows.Scan(&id, &appName, &ip, &ruleType, &note, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO ip_rules (id, app_name, ip, rule_type, note, created_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(6))
		if _, err := target.exec(q, id, appName, ip, ruleType, note, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateGeoRulesTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT id, app_name, country_code, rule_type, created_at FROM geo_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int
		var appName, countryCode, ruleType string
		var createdAt time.Time
		if err := rows.Scan(&id, &appName, &countryCode, &ruleType, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO geo_rules (id, app_name, country_code, rule_type, created_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(5))
		if _, err := target.exec(q, id, appName, countryCode, ruleType, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateAPIKeysTable(source, target *DB, overriding bool) (int, error) {
	// key_hash is deliberately included here (unlike ListAPIKeys, which
	// never selects it for display purposes) — without it a migrated key
	// would be a useless row that can never authenticate again.
	rows, err := source.query(`SELECT id, name, key_prefix, key_hash, created_at, last_used_at FROM api_keys`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int
		var name, prefix, hash string
		var createdAt time.Time
		var lastUsed sql.NullTime
		if err := rows.Scan(&id, &name, &prefix, &hash, &createdAt, &lastUsed); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO api_keys (id, name, key_prefix, key_hash, created_at, last_used_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(6))
		if _, err := target.exec(q, id, name, prefix, hash, createdAt, lastUsed); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateWAFDisabledRulesTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT id, rule_id, reason, created_at FROM waf_disabled_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var ruleID int
		var reason string
		var createdAt time.Time
		if err := rows.Scan(&id, &ruleID, &reason, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO waf_disabled_rules (id, rule_id, reason, created_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(4))
		if _, err := target.exec(q, id, ruleID, reason, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateWAFServiceExceptionsTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT id, service_name, rule_id, reason, created_at FROM waf_service_rule_exceptions`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var serviceName, reason string
		var ruleID int
		var createdAt time.Time
		if err := rows.Scan(&id, &serviceName, &ruleID, &reason, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO waf_service_rule_exceptions (id, service_name, rule_id, reason, created_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(5))
		if _, err := target.exec(q, id, serviceName, ruleID, reason, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateThreatIntelSourcesTable(source, target *DB, overriding bool) (int, error) {
	rows, err := source.query(`SELECT id, label, url, interval_hours, enabled, last_synced_at, last_error, ip_count, created_at FROM threat_intel_sources`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var label, url, lastSyncedAt, lastError string
		var intervalHours, ipCount int
		var enabled bool
		var createdAt time.Time
		if err := rows.Scan(&id, &label, &url, &intervalHours, &enabled, &lastSyncedAt, &lastError, &ipCount, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO threat_intel_sources (id, label, url, interval_hours, enabled, last_synced_at, last_error, ip_count, created_at)%s VALUES (%s)`,
			overridingClause(overriding), placeholders(9))
		if _, err := target.exec(q, id, label, url, intervalHours, boolToInt(enabled), lastSyncedAt, lastError, ipCount, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateThreatIntelIPsTable(source, target *DB, _ bool) (int, error) {
	rows, err := source.query(`SELECT source_id, ip FROM threat_intel_ips`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var sourceID int64
		var ip string
		if err := rows.Scan(&sourceID, &ip); err != nil {
			return n, err
		}
		if _, err := target.exec(`INSERT INTO threat_intel_ips (source_id, ip) VALUES (?, ?)`, sourceID, ip); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// migrateWebhookConfigTable copies the singleton webhook_config row (id=1,
// always pre-seeded by schema migration on the freshly-opened target) via
// the existing Get/SetWebhookConfig, which already handle the secret column
// correctly through each DB's own encryption state — no hand-rolled SQL
// needed, and no insert-vs-update branching since SetWebhookConfig always
// UPDATEs the pre-existing row rather than INSERTing a new one.
func migrateWebhookConfigTable(source, target *DB, _ bool) (int, error) {
	cfg, err := source.GetWebhookConfig()
	if err != nil {
		return 0, err
	}
	if err := target.SetWebhookConfig(cfg); err != nil {
		return 0, err
	}
	return 1, nil
}

func migrateIPThreatScoresTable(source, target *DB, _ bool) (int, error) {
	rows, err := source.query(`SELECT ip, total_score, autoban_score, bot_score, asn_score, geo_score, ja4_score, updated_at FROM ip_threat_scores`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var ip string
		var total, autoban, bot, asn, geo, ja4 int
		var updatedAt time.Time
		if err := rows.Scan(&ip, &total, &autoban, &bot, &asn, &geo, &ja4, &updatedAt); err != nil {
			return n, err
		}
		if _, err := target.exec(
			`INSERT INTO ip_threat_scores (ip, total_score, autoban_score, bot_score, asn_score, geo_score, ja4_score, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ip, total, autoban, bot, asn, geo, ja4, updatedAt,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateJA4ReputationTable(source, target *DB, _ bool) (int, error) {
	rows, err := source.query(`SELECT ja4, hits, blocked_hits, last_seen FROM ja4_reputation`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var ja4 string
		var hits, blockedHits int
		var lastSeen time.Time
		if err := rows.Scan(&ja4, &hits, &blockedHits, &lastSeen); err != nil {
			return n, err
		}
		if _, err := target.exec(
			`INSERT INTO ja4_reputation (ja4, hits, blocked_hits, last_seen) VALUES (?, ?, ?, ?)`,
			ja4, hits, blockedHits, lastSeen,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}
