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

## [2.8.0] - 2026-10-16

### Added

- Extra hostnames per service. In a service's new **Hosts** tab, list other names that should reach it, such as `www.example.com` next to `example.com`, and optionally pick one name the others redirect to (301 for GET and HEAD, 308 otherwise, path and query kept). The extra names share every setting and rule, automatic TLS issues certificates for them too, and the tab includes a short Cloudflare setup checklist. A hostname another service already uses is refused, and the API accepts `host_aliases` and `canonical_host`.
- A Redis area per service for app sessions. Connect Redis once in the new **Redis** card on Settings (`host:port`, or a `redis://` / `rediss://` URL for TLS, a username and a database number, which most hosted Redis needs), then turn it on in a service's new **Redis** tab. The tab shows a connection URL and key prefix to give the app. Where the server allows it, Palisade creates a Redis login for each service that can only touch keys starting with its prefix, so two apps sharing one Redis can't read each other's sessions; Redis that blocks this (such as Upstash) falls back to prefix-only, and the tab says which you got. Logins are re-created within a minute if Redis restarts, and removed when the service is deleted or the tab is turned off.

### Changed

- Redis is configured in its own Settings card rather than inside Rate Limiting, which now just picks Memory + SQLite or Redis. Choosing Memory no longer deletes the saved Redis connection. Existing setups keep using Redis for rate limiting with no change.

### Fixed

- The service settings modal is wider, so all of its tabs fit on one row.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.8.0...main
[2.8.0]: https://github.com/sinhaparth5/palisade-waf/compare/v2.7.0...v2.8.0
