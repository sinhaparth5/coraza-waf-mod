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

## [2.3.0] - 2026-09-27

### Added

- **ClickHouse analytics mirror** (#94, opt-in via `--warehouse-url`). The admin dashboard answers roughly fifteen questions, all hardcoded aggregates, and `--retention` deletes the underlying rows after 30 days — so anything nobody compiled in, or anything older than a month, is unanswerable. The WAF can now mirror its telemetry into a self-hosted ClickHouse for long-term analysis with a BI tool (Metabase, Grafana, Superset) on top. `waf_requests` streams live off the log-worker fan-out and reproduces every existing dashboard number over a year instead of a day; five dimension tables (`waf_ip_rules`, `waf_geo_rules`, `waf_services`, `waf_threat_scores`, `waf_ja4_reputation`) are snapshotted every 5 minutes so a join can answer "was this IP already banned when it hit us, and what was its score made of". The sink creates its own database and tables at startup, batches 1000 rows or 5 seconds per insert, and drops rather than blocking — like every other log hook it runs off the request path, so it adds no request latency. The operational store is untouched and stays the source of truth. Secret-bearing tables (`meta`, `api_keys`, `sessions`, `webauthn_credentials`, `webhook_config`, `certificates`, `threat_intel_sources`) and the `headers_json` column are never shipped, by allowlist. Reference stack in `deploy/docker-compose.analytics.yml`.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.3.0...main
[2.3.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.4...v2.3.0
