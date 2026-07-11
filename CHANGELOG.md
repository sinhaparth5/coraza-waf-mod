# Changelog

All notable changes to **Coraza WAF Mod** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.8] - 2026-07-11

### Added
- **WAF Rules**: rule exceptions can now be scoped to a single service
  instead of always applying globally. The disable form on the WAF Rules
  page gets a Scope selector (Global vs a specific service); scoped
  exceptions live in a new `waf_service_rule_exceptions` table and get their
  own compiled engine layered on top of the shared default one — built
  lazily, so services that never use this pay no extra memory for it. Fixes
  the common case of CRS rule 911100 ("Method is not allowed by policy" —
  CRS's default `allowed_methods` excludes PUT/PATCH/DELETE) blocking
  legitimate REST/CRUD APIs: an admin can now disable 911100 for just the
  one affected backend instead of losing HTTP method enforcement everywhere.
- **Performance**: geo country lookups (`geo.Blocker.Check`) and ASN/org
  lookups (`asn.Lookup.LookupForConn`) are now cached per TCP/TLS connection
  instead of re-queried on every request, mirroring the existing JA3/JA4
  per-connection cache. A keep-alive connection making many requests now
  pays for one mmdb lookup instead of one per request. Each cached entry
  also records the client IP it was computed for and is discarded on a
  mismatch, since a reverse proxy that multiplexes several real clients over
  one pooled connection to this origin (Cloudflare's connection pool
  behaves this way) would otherwise leak one client's country/ASN onto
  another's request sharing the same connection. Entries are cleared by the
  same TLS `ConnState` hook as JA3/JA4 on connection close, plus a
  background janitor (10-minute TTL) so plain-HTTP-only deployments — which
  have no `ConnState` hook at all — don't grow the cache unbounded.

## [1.4.7] - 2026-07-09

### Added
- **Threat score**: a unified per-IP composite risk score (0–100), summing
  autoban's current point total, the bot-analysis score, an ASN/hosting
  classification, a geo-risk flag reusing existing geo block rules, and a
  JA4 repeat-offender component backed by a new `ja4_reputation` table.
  Read-only for now — surfaced on the log detail modal and as a "Score N"
  badge per row on the IP Rules page, with a per-component breakdown so an
  admin can see *why* an IP scored what it did.
- **Adaptive enforcement**: threat-score-driven scaling of the global rate
  limit and forced bot challenges for high-risk clients, opt-in and off by
  default from a new "Adaptive enforcement" card on the IP Rules page.
  High-risk IPs (above a configurable threshold) get a tightened rate-limit
  burst/RPS and, past a stricter second threshold, a forced challenge
  regardless of per-service bot mode; low-risk IPs get a relaxed limit.
  Every adjustment is logged with an `:adaptive` action suffix alongside
  the normal block/challenge reasons, and re-evaluates the live score on
  every request — a scoring bug self-heals as soon as the score changes
  rather than leaving a permanent lockout. Paranoia-level tiering (the
  third lever originally proposed) was deliberately left out: Coraza bakes
  paranoia level into the compiled WAF engine at build time with no
  per-request override, so supporting it would mean holding multiple full
  pre-built engines in memory — tracked separately rather than built here.

### Changed
- The lint git hook now runs before every **commit** instead of only before
  a push (`.githooks/pre-commit`, was `pre-push`), and installs itself
  automatically the first time anyone runs `make build` or `make test` —
  `make hooks` still works but is no longer something every clone has to
  remember to run separately.

### Security
- **Services**: adding a backend now rejects cloud instance-metadata
  endpoints (`169.254.169.254`, AWS IMDSv2's `fd00:ec2::254`,
  `metadata.google.internal`), checked both against the literal host and
  its resolved IPs, before the add-service reachability probe ever contacts
  it (CodeQL `go/request-forgery`). Ordinary internal/private backends —
  the expected, legitimate use of this field — are unaffected.

## [1.4.6] - 2026-07-09

### Added
- **REST API**: `{admin.path}/api/v1/*`, authenticated with `Authorization:
  Bearer <key>` instead of the session cookie — a separate, CSRF-exempt Echo
  group for programmatic management. Covers full CRUD for services and IP
  rules, plus read/manual ban/unban for the ban list (backed by the same
  `ip_rules` table, filtered to global block rows). Keys are `cwaf_`-prefixed
  160-bit tokens shown once at creation and stored only as a SHA-256 digest;
  managed from a new API Keys card on the Settings page, with a one-click
  copy button on the one-time key display.
- **IP Rules**: paginated at 16 rows per page instead of loading the whole
  table — it can grow into the thousands via autoban. Prev/Next controls
  fetch a partial (`GET /admin/ip-rules/rows`) without a full page reload,
  mirroring the existing Services page pattern.
- **Logs**: a Table/Terminal toggle on the live Logs page. Terminal view is
  a dark, monospace panel streaming the same traffic in nginx combined log
  format (`IP - - [time] "request" status bytes "referer" "user-agent"`,
  `-` placeholders for the byte count and referer this project doesn't
  track). It preloads the last 24 hours of history on page load instead of
  starting empty, scrolls horizontally instead of soft-wrapping long lines,
  and only auto-follows new lines while already scrolled to the bottom —
  scrolling up to read history doesn't require a separate pause action.
  Backed by a new opt-in `--access-log` flag (plus
  `--access-log-max-size-mb`/`--access-log-max-backups`) that also writes
  the same lines to a rotating flat file for external tooling (fail2ban,
  log shippers, `logrotate`), independent of whether the live panel is open.
- **Linting**: `golangci-lint` (pinned `v2.12.2`, config in `.golangci.yml`)
  now runs both in CI (`.github/workflows/ci.yml`'s new `lint` job, which
  gates tag releases alongside the test job) and locally before every push
  via an opt-in git hook (`make hooks` once per clone, `.githooks/pre-push`).

### Changed
- Every implementation package moved under `internal/` and was regrouped by
  concern (`internal/security/` for detection/mitigation packages,
  `internal/notify/` for outbound reporting, etc.) — a folder-structure
  cleanup with no behavior change. See `CLAUDE.md`'s "Module layout" for the
  full tree if you're carrying a fork or an out-of-tree patch.

## [1.4.5] - 2026-07-08

### Added
- **Caching**: Opt-in per-service session-aware Varnish caching. Previously
  any request carrying a Cookie was refused caching outright; a service can
  now name its session cookie and have Varnish partition the cache per
  session instead — the WAF hashes the cookie's value (SHA-256, never the
  raw token) into `X-Cache-Session` before handing the request to Varnish,
  which folds it into the cache-hash key. Capped at a 10s TTL and off by
  default; services that don't opt in keep the original all-or-nothing
  Cookie behavior.
- **Caching**: Per-service TTL floor/ceiling and grace/keep tuning, replacing
  the previous hardcoded 1h asset floor and flat 30s grace. Configurable from
  the Services page; sent as headers by the WAF's Director and applied in the
  VCL via `std.duration()` — the VCL itself still never changes per service.
- **Caching**: A purge action (button + API) that immediately evicts
  everything Varnish has cached for one service — useful right after
  deploying new content to its backend. The WAF sends a `PURGE` request
  directly to Varnish over loopback (same trust model as the existing
  cache-return listener), which `ban()`s every object tagged with that
  service.

### Security
- Removed the `X-Protected-By` response header. `X-WAF-Engine` is kept, but
  advertising a dedicated "protected by" banner on every response made WAF
  fingerprinting by reconnaissance tools unnecessarily easy.

## [1.4.3] - 2026-07-08

### Fixed
- **Caching**: Varnish always reported `X-Cache: MISS`, even on repeated requests
  for static assets on a service with caching enabled. Varnish's built-in
  `vcl_backend_response` (appended after the custom one in `deploy/varnish/default.vcl`)
  independently marks a response uncacheable when it sees `Cache-Control:
  no-store`/`no-cache`/`private` or `Vary: *` — regardless of any ttl already
  set — and many backend frameworks attach exactly that to every response,
  including static files. Asset responses now have `Cache-Control` rewritten
  to a cacheable value (and a literal `Vary: *` stripped) so the admin's
  explicit per-service Cache toggle wins over a backend's default no-cache
  headers.

## [1.4.2] - 2026-07-08

### Added
- First release published from GitHub after migrating the repository from
  GitLab.
- GitHub Actions now runs tests on pushes and pull requests, then builds and
  publishes release binaries automatically when a `v*` tag is pushed.
- GitHub Release notes are now generated from the matching `CHANGELOG.md`
  version section, with install and checksum instructions appended
  automatically.
- Bot challenge now detects automated browsers. The challenge page probes for
  automation-leakage markers (`navigator.webdriver`, ChromeDriver `cdc_`/`$cdc_`
  arrays, `domAutomationController`, Selenium/Puppeteer/Playwright/PhantomJS/
  Nightmare globals, `HeadlessChrome` UA) and reports them with the proof-of-work
  solution; the server refuses the bypass cookie when any is present. Headless
  scanners (e.g. OWASP ZAP's browser-driven mode) that previously solved the PoW
  and earned a trusted session are now kept at the challenge — where the autoban
  scorer eventually bans the IP for the repeated unsolved redirects.

### Changed
- Replaced the GitLab CI/CD pipeline with GitHub Actions.
- Updated the installer to discover releases through the GitHub API and download
  binaries plus checksums from GitHub Release assets instead of GitLab's package
  registry.
- Updated contributor and release documentation for GitHub pull requests,
  Actions, release downloads, and compare links.

### Fixed
- Removed the unused `config.yaml` / `deploy/config.yaml.example` files and
  every doc/UI reference to a config-file-driven setup. The server has taken
  CLI flags only for some time (`main.go` never parsed YAML), but `README.md`,
  `CONTRIBUTING.md`, `AGENTS.md`, `docker-compose.yml`, the two static
  `deploy/coraza-waf-mod*.service` reference units, and two labels on the
  Services page still described the old config.yaml/`admin.path`/`apps:`
  seeding flow. All now match actual behavior: bootstrap settings are CLI
  flags, admin credentials are seeded via `coraza-waf-mod setup`, and
  `docker-compose.yml` passes flags via `command:` instead of a mounted
  config file.
- `install.sh`: the Varnish systemd drop-in now passes `-F` to `varnishd`.
  Without it, varnishd daemonized under the stock `Type=notify` unit and systemd
  terminated the service (`SIGTERM`, exit 0) a fraction of a second after start,
  so `systemctl start varnish` never stayed running.
- Threat Intel page: Remove / Sync / Pause buttons no longer break after the
  rows are re-rendered as an HTMX partial (e.g. right after adding a feed). The
  partial now carries `AdminPath`, so the action URLs resolve correctly instead
  of producing a bogus path that silently 404'd.

## [1.3.0] - 2026-07-04

### Added
- **Varnish cache integration** — per-service "Cache" toggle on `/admin/services`
  routes traffic through a loopback Varnish sandwich (client → WAF → varnishd →
  WAF cache-return listener → backend). VCL is static and never changes when
  services do; everything is UI-driven with no restart or `systemctl reload`.
  Includes cache-poisoning defenses (spoofable header scrubbing, loopback-only
  binds, hash partitioning by `X-Cache-Service`).

### Changed
- Redesigned the Services page.
- Improved IP blocking behaviour.

### Fixed
- Fixed a record-deletion bug in the admin UI.

## [1.2.0] - 2026-07-02

### Added
- **Automatic IP banning (autoban)** — scores blocked events per client IP over
  a sliding window and writes a permanent global block rule once the threshold
  is crossed, with an amber "Auto" badge on the IP Rules page. Configurable from
  the "Automatic banning" card; applies live with no restart.
- **Daily report & ban-alert email** via Cloudflare Email Service — end-of-day
  traffic summary plus real-time ban alerts. Recipient list and API token are
  configured from the Settings page; the token is never shipped in the repo or
  binary.

### Changed
- Reworked the Settings page and tightened the Cloudflare email configuration.

## [1.1.0] - 2026-07-02

### Added
- **JA4 TLS fingerprinting** — computed at handshake time, stored in the request
  log and shown in the UI; now the primary fingerprint.
- **FingerprintJS browser visitor ID** — vendored bundle served from `/_cz/fp.js`,
  run on the challenge page and HMAC-bound into the bypass cookie. Drives the
  dashboard "Unique visitors" card.
- **CSRF protection** — stateless per-session tokens on all non-GET admin routes.
- Dashboard "At a glance" and geo-distribution cards now show real data from the
  database instead of placeholders.

### Changed
- Hardened admin login security (per-IP brute-force throttling).
- Updated the bot challenge page and certificate creation flow.

### Deprecated
- **JA3 fingerprinting** — retained only for continuity with existing log data;
  do not build new detection on it. Use JA4 instead.

### Removed
- Removed the unused code-review page and stopped tracking a local `waf.db`.

## [1.0.1] - 2026-06-28

### Fixed
- Graceful shutdown on `SIGINT`/`SIGTERM` so in-flight requests complete and the
  log queue drains before exit.
- Trusted-proxy handling for forwarded client IPs (`X-Forwarded-For` / `X-Real-IP`).
- Non-fatal HTTP redirect-listener errors no longer crash startup.
- JA3 per-connection store is now cleaned up when the TLS connection closes.

## [1.0.0] - 2026-06-27

Initial release — a single-binary Go WAF + reverse proxy.

### Added
- **Coraza v3 WAF** with the embedded OWASP Core Rule Set (SQLi, XSS, RCE, path
  traversal, scanner UAs, etc.), plus support for custom `.conf` rules.
- **Reverse proxy / multi-app routing** by Host header (virtual hosting) or path
  prefix (with automatic prefix stripping).
- **TLS** — plain HTTP, automatic Let's Encrypt (ACME), or uploaded cert/key,
  globally and per service.
- **IP & country blocking** — manual allow/block rules plus bundled MaxMind
  GeoLite2 country blocking, with Cloudflare-aware real-IP extraction.
- **Rate limiting** — in-process token bucket or Redis-backed distributed
  limiting, with per-service overrides.
- **Bot challenge** — JS proof-of-work gate for low-reputation clients, with a
  trusted-crawler allowlist.
- **Prometheus metrics** at `{admin.path}/metrics`.
- **HTMX + Tailwind admin dashboard** — live traffic/threat charts, filterable
  request logs with SSE live tail, and IP/geo/service/certificate/WAF-rule
  management, all applied without a restart.
- **All storage in SQLite** (`modernc.org/sqlite`, pure Go, no CGO) — one
  `waf.db` file for logs, rules, services, and TLS state.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.4.2...main
[1.4.2]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.3.0...v1.4.2
[1.3.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sinhaparth5/coraza-waf-mod/releases/tag/v1.0.0
