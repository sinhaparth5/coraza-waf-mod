# Changelog

All notable changes to **Palisade** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file deliberately keeps only two sections: **[Unreleased]**, where changes
accumulate, and the **most recently published version**, kept so the current
release is readable without leaving the repo. `make tag VERSION=vX.Y.Z` promotes
Unreleased into a new version section, drops the previous one, and opens a fresh
Unreleased — older entries stay available in their git tags and GitHub releases
rather than growing this file forever.

## [Unreleased]

## [2.6.0] - 2026-10-15

### Added

- HTTP/3 (QUIC), opt-in per service. Start Palisade with `--listen-h3 :443` (the installer now passes it) and allow UDP 443, then turn on **HTTP/3** in a service's TLS tab. Only those domains advertise HTTP/3 (`Alt-Svc`); HTTP/2 stays the default and fallback for everything else, including the admin UI. The full WAF pipeline runs unchanged, 0-RTT is disabled, and JA4 fingerprints from QUIC handshakes start with `q`. Also settable through the API as `http3_enabled`.

### Changed

- Redesigned the report, ban-alert and login-code emails to match the admin UI's current look (colours, Calistoga / DM Sans / JetBrains Mono). The daily report now adds an hourly traffic chart with the busiest hour marked, a breakdown of which stage blocked what, top blocked countries, IPs and WAF rules, and a comparison with the previous day. The charts are built from HTML tables, so they show up in Gmail too.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.6.0...main
[2.6.0]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.3...v2.6.0
