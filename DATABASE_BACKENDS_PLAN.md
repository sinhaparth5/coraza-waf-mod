# Pluggable external database backends (MySQL/MariaDB/Postgres/CockroachDB/Neon)

Status: **not started**.

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
- [ ] Add `sqlx`, `go-sql-driver/mysql`, `pgx/v5/stdlib` to `go.mod`.
- [ ] Introduce a small `dialect` type in `internal/storage/` capturing:
      driver name, autoincrement keyword, upsert-clause builder function,
      placeholder rebind, connection-pool tuning (PRAGMA string for sqlite vs
      `SetMaxOpenConns` etc. for the others).
- [ ] Swap the single `sql.Open` + raw `*sql.DB` for `sqlx.Open` +
      `*sqlx.DB` (drop-in compatible with existing `Exec`/`Query`/`QueryRow`
      calls, since `sqlx.DB` embeds `*sql.DB`) — this step alone should be
      a no-op for the SQLite path, provable by the full existing test suite
      passing unmodified.

### Phase 1 — CLI/config plumbing
- [ ] Add `--db-driver` flag to `internal/config`, threaded through
      `main.go`'s `storage.Open`-equivalent call.
- [ ] `storage.Open` (or a new `storage.OpenWithDriver`) picks the DSN/driver
      combination and applies dialect-appropriate connection tuning.
- [ ] Keep the zero-flag default path (`sqlite`, `--db waf.db`) byte-for-byte
      identical in behavior — every existing deployment must not need to
      change anything.

### Phase 2 — schema and migrations
- [ ] Rewrite the 16 `CREATE TABLE IF NOT EXISTS` statements to be built via
      the `dialect` type's autoincrement/type substitutions rather than
      hardcoded SQLite syntax.
- [ ] Rewrite the 33 `ALTER TABLE ADD COLUMN` migrations to branch on
      dialect capability (native `IF NOT EXISTS` vs swallow-the-error).
- [ ] Rewrite the 8 `ON CONFLICT` upserts per dialect (`ON DUPLICATE KEY
      UPDATE` for MySQL).
- [ ] Audit boolean-column handling across all three backends (SQLite has no
      native `BOOLEAN`; confirm each driver round-trips Go `bool` the same
      way the existing code already assumes).

### Phase 3 — dialect-specific behavior in one-shot commands
- [ ] `coraza-waf-mod prune --vacuum`: implement or explicitly no-op/warn
      per driver (SQLite `VACUUM`+WAL truncate already exists; decide
      Postgres/MySQL behavior and document it — don't silently do nothing
      without telling the operator).
- [ ] Re-verify `coraza-waf-mod setup`/`gencert` (which touch the DB) work
      unmodified against every backend.

### Phase 4 — testing
- [ ] Stand up MySQL + Postgres service containers for CI (docker-compose
      or `services:` blocks in `ci.yml`).
- [ ] Run the full existing `internal/storage` test suite against both new
      backends via a `TEST_DB_DSN`-driven `Open` in test setup, gated so
      default `go test ./...` doesn't require Docker/network.
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
