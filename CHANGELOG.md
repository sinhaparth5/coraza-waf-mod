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

### Added

- HTTP/3 (QUIC), opt-in per service. Start Palisade with `--listen-h3 :443` (the installer now passes it) and allow UDP 443, then turn on **HTTP/3** in a service's TLS tab. Only those domains advertise HTTP/3 (`Alt-Svc`); HTTP/2 stays the default and fallback for everything else, including the admin UI. The full WAF pipeline runs unchanged, 0-RTT is disabled, and JA4 fingerprints from QUIC handshakes start with `q`. Also settable through the API as `http3_enabled`.

## [2.5.3] - 2026-10-15

### Security

- The bot-challenge page now also checks its post-solve redirect in the browser and only follows same-origin `http(s)` paths, falling back to `/`. The server has filtered this value since v2.2.4, so this is defense in depth and closes CodeQL alert `js/xss-through-dom`.

### Fixed

- Shutting down now waits for in-flight session and API-key "last used" writes before closing the database, instead of letting them fail against a closed connection (also caused flaky `internal/ui` tests in CI).

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.3...main
[2.5.3]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.2...v2.5.3
