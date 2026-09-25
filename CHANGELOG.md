# Changelog

All notable changes to **Coraza WAF Mod** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file deliberately keeps only two sections: **[Unreleased]**, where changes
accumulate, and the **most recently published version**, kept so the current
release is readable without leaving the repo. `make tag VERSION=vX.Y.Z` promotes
Unreleased into a new version section, drops the previous one, and opens a fresh
Unreleased — older entries stay available in their git tags and GitHub releases
rather than growing this file forever.

## [Unreleased]

## [2.2.0] - 2026-09-25

### Added

- Health probes: `/_cz/healthz` (liveness) and `/_cz/readyz` (database reachable), unauthenticated on every host and left out of the stdout request log, plus a `coraza-waf-mod healthcheck` subcommand that the Docker image now uses as its `HEALTHCHECK` (#1).
- `--prune-interval` flag that prunes old request logs and expired sessions in-process at the given interval, for deployments with no cron or systemd timer (#87).
- `GET /admin/api/v1/metrics`: the Prometheus metrics, reachable with a bearer API key (a read-only key is enough), so a scrape job can authenticate (#88).

### Fixed

- Docker containers never pruned request logs, so the database grew without bound whatever `--retention` said; the image now runs with `--prune-interval 24h` (#87).
- The `postgres:18` test container in `docker-compose.test.yml` exited on start because of Postgres 18's new data directory layout (#89).

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.0...main
[2.2.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.1.0...v2.2.0
