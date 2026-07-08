# Changelog

All notable changes to **Coraza WAF Mod** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
