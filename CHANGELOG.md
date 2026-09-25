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

## [2.2.3] - 2026-09-25

### Added

- **Create a WAF exception from the log view** (#7). A blocked request's detail modal now has a **Create exception** button. It disables the rule that blocked the request for that request's service only, and the WAF reloads live. The rule and service are read from the stored log row, never from the browser. The exception shows up under **Per-Service Exceptions** on the WAF Rules page, where you can re-enable the rule.
- **WAF rule dry-run** (#8). The WAF Rules page has a new **Dry-run Rules** card. Paste candidate rules and replay the last N logged requests (up to 2000) through two throwaway engines: the current global rules, and the current rules plus your candidate. The card lists every request whose verdict would change. Nothing is saved and live traffic is never touched. Request bodies aren't logged, so rules that inspect bodies can't match during replay.

### Changed

- CI now builds with Go 1.27 to match `go.mod`. Before this, every job failed with `go.mod requires go >= 1.27.0`. golangci-lint moved to v2.14.0, the first release built with Go 1.27.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.3...main
[2.2.3]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.2...v2.2.3
