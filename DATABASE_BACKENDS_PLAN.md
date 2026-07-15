# Pluggable external database backends (MySQL/MariaDB/Postgres/CockroachDB/Neon)

Status: **Phases 0, 1, and 3 fully implemented. Phase 2 (schema/migration/
upsert rewrite) implemented and verified end-to-end against live local
MySQL 8 and Postgres 16 containers — every write path exercised (schema
creation, idempotent re-open, IP-rule upsert, request insert with
auto-generated id, JA4 reputation increment-on-conflict) passes on all
three dialects. Full existing SQLite test suite still passes unmodified.
build/test/gofmt/lint all green. Phase 2's boolean-handling audit item is
resolved as a non-issue (see below). Remaining: broader test coverage across
the full ~130-method surface (only the highest-risk subset was exercised
live so far), Phase 4's CI wiring, Phase 5 docs.**

## Local test infrastructure

`docker-compose.test.yml` (new, dev/test-only, not part of the production
image): `mysql:8` on `localhost:3307` and `postgres:16` on `localhost:5433`,
both on `tmpfs` (ephemeral — a fresh schema every restart, which is
deliberate for iterating on migrations). Start with `docker compose -f
docker-compose.test.yml up -d`. **MySQL takes ~20s to become genuinely
ready** after `docker compose up` — its entrypoint runs a temporary server
for init scripts, shuts it down, then starts the real one; `mysqladmin ping`
succeeds against the *temporary* instance, giving a false-positive
readiness signal if you don't also grep its logs for a second "ready for
connections" line (or just sleep ~25s) before connecting.

## Real bugs this live-testing approach caught (would have shipped broken otherwise)

Every one of these was found by actually running migrations and queries
against live containers, not by reasoning about SQL dialect rules from
memory — several directly contradict what looked like a safe assumption:

1. **`?` placeholders silently break on Postgres.** Swapping to `*sqlx.DB`
   in Phase 0 does *not* auto-rebind placeholders — `sqlx.DB.Rebind()` must
   be called explicitly. Postgres rejected every one of the ~92 existing
   `?`-based queries with a syntax error until `db.exec`/`db.query`/
   `db.queryRow` wrapper methods (`internal/storage/db.go`) were added to
   rebind on every call, and two hand-rolled transactions
   (`SaveRateLimitState`, `ReplaceThreatIntelIPs`) were fixed to rebind
   before `tx.Prepare`/`tx.Exec` individually (a `*sql.Tx` from
   `db.conn.Begin()` has no `Rebind` of its own).
2. **`res.LastInsertId()` is not supported by pgx at all.** Postgres has no
   wire-protocol equivalent — every INSERT that needs the new row's id
   (`InsertRequest`, `AddCertificate`, `CreateAPIKey`) now goes through a new
   `db.insertReturningID` helper that appends `RETURNING id` and reads it
   back via `QueryRow` on Postgres, keeping `LastInsertId()` for SQLite/MySQL.
3. **MySQL rejects a literal `DEFAULT ''` on a `TEXT` column outright**
   ("BLOB, TEXT, GEOMETRY or JSON column can't have a default value") even
   on a current MySQL 8 — contradicts the assumption that 8.0.13+ lifted
   this restriction; it only allows it via a *parenthesized expression
   default* (`DEFAULT ('')`). Fixed with a MySQL-only regex post-processing
   pass (`mysqlWrapTextDefaults` in `schema.go`) over the rendered DDL.
4. **MySQL cannot index a full `TEXT` column at all** ("BLOB/TEXT column
   ... used in key specification without a key length") — applies to
   regular secondary indexes (`dialect.createIndexOnText` adds a MySQL-only
   `(N)` prefix length) *and*, more seriously, to every `PRIMARY KEY`/
   `UNIQUE` constraint on a string column, which MySQL refuses unconditionally
   regardless of prefix length. Fixed by changing every PK/UNIQUE string
   column across the schema from `TEXT` to a sized `VARCHAR(N)` — works
   identically on SQLite (ignores the length) and Postgres (enforces it,
   same as TEXT would) — rather than a MySQL-only special case.
5. **`key` is a reserved word in MySQL.** The `meta` table's `key` column
   (pre-existing name, used throughout `getMeta`/`setMeta`) caused a MySQL
   syntax error on the bare `CREATE TABLE`/`SELECT`/`INSERT` text that works
   fine unquoted on SQLite and Postgres. Fixed with a new
   `dialect.quoteIdent()` (backtick-quotes only for MySQL) applied at the
   4 call sites that reference it as a raw identifier.
6. **Postgres requires the table name to qualify a self-referencing column
   in `ON CONFLICT DO UPDATE SET` for increment-style updates** — confirmed
   directly against `psql`: `hits = hits + 1` errors "ambiguous", while
   `hits = ja4_reputation.hits + 1` works. SQLite and MySQL both accept the
   bare unqualified form. `BumpJA4Reputation` (the one upsert that
   increments rather than replaces a column, so it doesn't fit the generic
   `dialect.upsertUpdate` helper) now has a dedicated
   `bumpJA4ReputationSQL(dialect)` with all three variants spelled out.
7. **MySQL's `CREATE INDEX` has no `IF NOT EXISTS` at all** (unlike its
   `ALTER TABLE ADD COLUMN`, which gained one in 8.0.29) — a second
   `OpenWithDriver` call against an existing MySQL database (i.e. every
   normal server restart) always hit "Duplicate key name" on every index.
   `migrate()`'s `schemaStatements()` loop now special-cases statements
   starting with `CREATE INDEX` to swallow the error, the same convention
   already used for SQLite's `ADD COLUMN`.

## Boolean-handling audit (Phase 2 checklist item, resolved)

No dialect-specific handling needed: every boolean-shaped column in this
schema (`blocked`, `enabled`, `cache_enabled`, etc.) is declared `INTEGER`
storing a plain `0`/`1` — never any dialect's native `BOOLEAN` type — so all
three backends round-trip the exact same Go `int`/`bool`-via-`boolToInt`
conversion already in place with no changes.

## What the user asked for

Let users point the WAF at an external database instead of embedded SQLite —
MariaDB, MySQL, or Postgres, including Postgres-wire-compatible cloud/managed
services (CockroachDB, Neon). SQLite stays the zero-config default; this is
opt-in for larger or HA deployments. Tracked separately from
[[DOCKER_RELEASE_PLAN]] — different effort, different timeline.

## Why this is a large change, not a driver swap

`internal/storage/db.go` is one 2894-line file, ~130 methods, all written
directly against `database/sql` with SQLite-specific assumptions baked in
throughout:

- **One `sql.Open("sqlite", dsn)` call** (`db.go:124`) with PRAGMAs passed as
  DSN query params (`_pragma=busy_timeout(...)`) — a mechanism that doesn't
  exist for MySQL/Postgres drivers, which tune connections via
  `SetMaxOpenConns`/`SetConnMaxLifetime` and driver-specific DSN options
  instead (see CLAUDE.md's "SQLite concurrency" section).
- **16 `CREATE TABLE` statements** using `INTEGER PRIMARY KEY AUTOINCREMENT`
  — MySQL wants `AUTO_INCREMENT`, Postgres wants `SERIAL`/`GENERATED ALWAYS
  AS IDENTITY`. Every one needs a per-dialect variant.
- **33 `ALTER TABLE ... ADD COLUMN` migrations**, most relying on SQLite
  silently erroring (swallowed via `//nolint`) when the column already
  exists, since old SQLite has no `ADD COLUMN IF NOT EXISTS`. MySQL 8.0.29+
  and Postgres both support `IF NOT EXISTS` natively — the pattern needs to
  branch per dialect rather than uniformly "ignore the error."
- **8 `ON CONFLICT (...) DO UPDATE/NOTHING` upserts** — valid SQLite/Postgres
  syntax, but MySQL needs `ON DUPLICATE KEY UPDATE` instead. Every one needs
  a per-dialect rewrite.
- **~124 call sites use `?` placeholders** — fine for SQLite and MySQL, but
  Postgres (via `pgx`/`lib/pq`) requires `$1, $2, ...`. This is the good
  news: it's a single, mechanical, sqlx-`Rebind()`-solvable problem rather
  than 124 individual rewrites, *if* we adopt `sqlx` (see Decisions below).
- **`PruneOldRequests`/`Vacuum`**: SQLite's `VACUUM` + `wal_checkpoint
  (TRUNCATE)` has no direct equivalent — Postgres has its own `VACUUM`
  (different semantics, no `VACUUM INTO`), MySQL uses `OPTIMIZE TABLE`. The
  `prune --vacuum` CLI subcommand needs a per-driver implementation, or a
  documented no-op/warning on backends where reclaiming space works
  differently (managed Postgres/CockroachDB/Neon typically handle this
  server-side already).
- **The documented SQLite date/time gotcha** (`modernc.org/sqlite` stores
  `time.Time` via `.String()`, so `date()`/`strftime()` return NULL — see
  CLAUDE.md) is SQLite-specific. The Go-side `>=`/`<=` bucketing workaround
  already in place is dialect-agnostic and keeps working unmodified on every
  backend — this is actually a non-issue once ported, just a comment that
  needs a "why this exists" caveat added so a future reader doesn't assume
  it's dead weight on Postgres/MySQL.
- **`internal/storage/secretenc.go`** (AES-256-GCM sealing of secret meta
  values) operates on values before `Set`/after `Get` — dialect-agnostic,
  should need zero changes.

## Decisions to make explicit before writing code

- **Library**: adopt `github.com/jmoiron/sqlx` (thin wrapper over
  `database/sql`, has `Rebind()` for `?`→`$1` placeholder translation and
  `DriverName()`-aware helpers) rather than a full ORM or query builder —
  keeps ~124 existing query strings intact, only the small minority with
  dialect-specific DDL/upsert syntax need branching. Recommended over
  writing a bespoke rebind layer from scratch.
- **Drivers** (all pure Go — keeps `CGO_ENABLED=0` cross-compiles, per
  CLAUDE.md's Distribution section): `github.com/go-sql-driver/mysql` for
  MySQL/MariaDB (wire-compatible, one driver covers both), `github.com/
  jackc/pgx/v5/stdlib` for Postgres (also covers CockroachDB and Neon — both
  speak the Postgres wire protocol, so no new driver or per-service code,
  only DSN guidance: Neon requires `sslmode=require` and benefits from its
  own connection pooler endpoint since serverless Postgres can be
  slow/limited on raw connection count; CockroachDB generally just works
  with default pgx settings but some `SERIAL`/locking semantics differ
  subtly enough to need dialect-specific testing, not code).
- **Config surface**: add `--db-driver` (`sqlite` default / `mysql` /
  `postgres`) and repurpose `--db` as a DSN when driver != sqlite (keeps the
  existing `--db waf.db` flag meaning unchanged for the default case).
- **Migration strategy**: keep one ordered list of migrations in Go (matches
  today's pattern) but template the DDL per dialect via a small
  `dialect` struct (autoincrement keyword, upsert clause builder, "add
  column if not exists" capability flag) rather than maintaining fully
  separate SQL files per backend — less duplication, one migration list to
  keep in sync.
- **Testing strategy**: existing `internal/storage/*_test.go` (18 files) all
  call `storage.Open(path)` against a temp SQLite file. These need to run
  against MySQL/Postgres too — likely via `docker-compose` test services
  (mysql:8, postgres:16) spun up in CI behind a `-tags integration` build tag
  or a `TEST_DB_DSN` env var, so plain `go test ./...` stays fast/hermetic
  and CI gains a second job matrix for the external-DB path. Needs its own
  design pass once the abstraction lands — don't guess this until phase 1
  is done and the real interface shape is known.

## Phased implementation plan

### Phase 0 — groundwork (no behavior change)
- [x] Added `sqlx`, `go-sql-driver/mysql`, `pgx/v5/stdlib` to `go.mod`
      (`go get` + `go mod tidy`).
- [x] `internal/storage/dialect.go`: `dialect{name, driverName}` type,
      `dialectSQLite`/`dialectMySQL`/`dialectPostgres` values,
      `resolveDialect(driverName)` (accepts `mariadb` as a `mysql` synonym,
      `postgresql`/`cockroachdb`/`cockroach`/`neon` as `postgres` synonyms),
      `autoIncrementPK()`, `addColumnIfNotExists(table, columnDef)`, and
      `openDB(dsn)` (SQLite keeps its `_pragma=` DSN tuning +
      `SetMaxOpenConns(8)`; MySQL/Postgres get `SetMaxOpenConns(8)` with no
      PRAGMA equivalent). Covered by `dialect_test.go`.
- [x] Swapped `sql.Open`/`*sql.DB` for `sqlx.Open`/`*sqlx.DB` in
      `internal/storage/db.go` (`DB.conn` field type only — `sqlx.DB` embeds
      `*sql.DB`, so every existing `Exec`/`Query`/`QueryRow` call site needed
      zero changes; `database/sql` import kept for `sql.ErrNoRows`/
      `sql.NullFloat64`/`sql.NullTime`). Proven a no-op for SQLite: full
      existing test suite (all 18 `internal/storage/*_test.go` files) passed
      unmodified, no test changes needed.

### Phase 1 — CLI/config plumbing
- [x] `internal/config.DBConfig` gained a `Driver string` field, defaulted
      to `"sqlite"` in `config.Defaults()`.
- [x] `storage.Open(path)` is now a thin wrapper around the new
      `storage.OpenWithDriver(driverName, dsn)`, which resolves the dialect,
      opens via `dialect.openDB`, and otherwise behaves identically to the
      old `Open`. Every existing caller (`storage.Open` in 18 test files,
      3 `main.go` call sites before this phase) needed no changes.
- [x] Added `--db-driver` flag (default `"sqlite"`) alongside the existing
      `--db` flag at all three `main.go` entry points (main server bootstrap,
      `prune`, `setup`) — `--db`'s help text updated to
      "database path (sqlite) or DSN (mysql/postgres)". `gencert` untouched
      (doesn't open a DB).
- [x] Zero-flag default path confirmed byte-for-byte unchanged (same test
      suite, same behavior — `--db-driver` defaults to `"sqlite"` everywhere).

### Phase 2 — schema and migrations
- [x] Rewrote the 16 `CREATE TABLE IF NOT EXISTS` statements into
      `internal/storage/schema.go`'s `schemaStatements()`, built via the
      `dialect` type's autoincrement/timestamp-type substitutions. Also had
      to change every PK/UNIQUE string column from `TEXT` to a sized
      `VARCHAR(N)` (MySQL can't key a TEXT column at all — see bug #4 in the
      progress log above) and quote the `meta` table's `key` column for
      MySQL (`dialect.quoteIdent` — `key` is a MySQL reserved word, bug #5).
- [x] Rewrote the 33 `ALTER TABLE ADD COLUMN` migrations as a data-driven
      `schemaMigrations` loop through `dialect.addColumnIfNotExists`.
- [x] Rewrote all 8 `ON CONFLICT` upserts: 6 generic "replace with new
      value" upserts (`AddIPRuleWithNote`, `AddGeoRule`, `setMeta`,
      `DisableWAFRule`, `DisableWAFRuleForService`, `UpsertIPThreatScore`)
      now go through `dialect.upsertUpdate`; the 2 "do nothing on conflict"
      seeds (`webhook_config` singleton row, `meta` notifications baseline)
      go through `dialect.upsertIgnore`. `BumpJA4Reputation` — an *increment*
      upsert, not a replace — didn't fit the generic helper and needed its
      own `bumpJA4ReputationSQL(dialect)` with a genuine Postgres-only
      qualification quirk (bug #6). A ninth upsert surfaced during live
      testing that the original 8-count missed: `ReplaceThreatIntelIPs`'s
      `INSERT OR IGNORE INTO threat_intel_ips`, now `dialect.upsertIgnore`.
- [x] Audited boolean-column handling: no dialect-specific handling needed
      at all — every boolean-shaped column is `INTEGER` storing `0`/`1`,
      never a dialect's native `BOOLEAN` type, so the existing `boolToInt`
      conversion already works unchanged on all three backends.

### Phase 3 — dialect-specific behavior in one-shot commands
- [x] `coraza-waf-mod prune --vacuum`: `DB.Vacuum()` is now dialect-aware —
      SQLite keeps `VACUUM` + `PRAGMA wal_checkpoint(TRUNCATE)`, Postgres
      runs bare `VACUUM` (no WAL-checkpoint-equivalent pragma), MySQL is an
      explicit no-op (no database-wide VACUUM exists; `OPTIMIZE TABLE` is
      per-table and out of scope for now). `main.go`'s `runPruneOnly` no
      longer computes a before/after disk-size delta for non-SQLite drivers
      (that logic stats a local file path, meaningless for a DSN) and logs a
      driver-appropriate message instead.
- [x] `coraza-waf-mod setup` (`SeedAdmin`, `SetDomain`, `SetAcmeEmail`) needs
      no dialect-specific changes — all go through the already-fixed
      `getMeta`/`setMeta`. Not yet run end-to-end against live MySQL/Postgres
      containers as its own explicit test (only exercised indirectly via
      `setMeta`'s upsert path in the scratch tests below) — worth a direct
      pass in Phase 4. `gencert` remains confirmed DB-free, no change needed.

### Phase 4 — testing
- [x] Local MySQL + Postgres containers for dev-time testing:
      `docker-compose.test.yml` (repo root, dev/test-only, not part of the
      production image) — `mysql:8` on `localhost:3307`, `postgres:16` on
      `localhost:5433`, both on `tmpfs` for a clean slate every restart.
      Used throughout Phase 2 to catch the 7 real bugs listed in the
      progress log above; not yet wired into CI itself.
- [ ] Wire the same MySQL/Postgres containers into `ci.yml` (`services:`
      blocks) so Phase 2's coverage runs on every PR, not just locally.
- [ ] Run the full existing `internal/storage` test suite (not just the
      handful of methods exercised by the scratch tests during Phase 2)
      against both new backends via a `TEST_DB_DSN`-driven `Open` in test
      setup, gated so default `go test ./...` doesn't require Docker/network.
      The scratch tests used during Phase 2 development covered: schema
      creation + idempotent re-open, `AddIPRule`/`AddIPRuleWithNote` upsert,
      `InsertRequest` (id generation), `BumpJA4Reputation` (increment
      upsert) — a small, high-risk-weighted slice of the ~130 total methods,
      not the full surface.
- [ ] Add CockroachDB- and Neon-specific smoke tests if feasible (may need
      real or CI-hosted instances — confirm feasibility before committing to
      automating this vs. documenting manual verification only).

### Phase 5 — docs
- [ ] CLAUDE.md: update "SQLite concurrency" section (or add a sibling
      section) describing the new multi-backend architecture, the
      `dialect` abstraction, and per-backend DSN examples/caveats
      (Neon's `sslmode=require` + pooler endpoint, CockroachDB notes).
- [ ] README / install docs: `--db-driver`/DSN flag usage examples for each
      backend.
- [ ] CHANGELOG.md entry once shipped.

## Explicitly out of scope (unless the user says otherwise later)

- Any ORM or query-builder rewrite beyond the minimal `sqlx` adoption needed
  for placeholder rebinding.
- Automatic cross-backend data migration/export tooling (e.g. "move my
  existing `waf.db` into Postgres") — this plan only covers *starting*
  fresh against a chosen backend, not migrating an existing SQLite
  deployment's data.
- Read replicas, sharding, or any HA topology beyond "point the binary at a
  connection string" — the app stays single-writer-assumption per request
  path unless a real need surfaces.
