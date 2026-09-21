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

## [1.9.6] - 2026-09-21

### Fixed

- **API key creation was broken on Postgres.** `CreateAPIKey` bound the raw
  Go `bool` for the new read-only flag (issue #73) straight into an
  `INTEGER` column instead of converting it first, the convention every
  other boolean column in the store follows. SQLite and MySQL coerce that
  silently; Postgres's driver enforces its wire types strictly and rejected
  the insert outright, so no deployment on `--db-driver postgres` could
  create an API key at all. Fixed and verified against a live Postgres
  instance (#74).

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.9.6...main
[1.9.6]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.9.5...v1.9.6
