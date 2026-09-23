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

## [2.0.2] - 2026-09-23

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

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.2...main
[2.0.2]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.1...v2.0.2
