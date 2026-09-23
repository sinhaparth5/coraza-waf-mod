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

### Added

- **AI Usage page** (`/admin/ai-usage`) showing every Jev API call the
  TypeSafe-backed ASN/hosting classifier (Settings' "AI Classification"
  card) has made — timestamp, ASN, organization, hosting verdict, input/
  output token counts, duration, and any error — plus 24h/7d call and
  token totals. The classifier previously wasn't logged anywhere and
  didn't even parse the API's `usage` field, so there was no way to see
  where TypeSafe token usage was going. Logged to a new capped
  `typesafe_calls` table (newest 2000 rows).

  Note: `classifyASN` still only caches a *successful* Jev judgment — an
  erroring call (bad key, rate limit, timeout) leaves the ASN uncached, so
  every subsequent request from that ASN re-triggers a fresh API call
  instead of the intended once-ever-per-ASN. Not changed by this release;
  now at least visible per-call via the AI Usage page's error column
  instead of only a one-line stderr log.

## [2.0.1] - 2026-09-21

### Fixed

- **`webauthn_credentials.credential_id` broke on MySQL.** The new passkey
  table (v2.0.0) declared it as a plain `UNIQUE TEXT` column — MySQL
  refuses a `TEXT`/`BLOB` column in a key specification without an
  explicit length, so no MySQL-backed deployment could even open its
  database, let alone use passkeys. Sized to `VARCHAR(768)`, matching the
  existing `threat_intel_sources.url` precedent, and verified against a
  live `mysql:8` instance.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.1...main
[2.0.1]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.0...v2.0.1
