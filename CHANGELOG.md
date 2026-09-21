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
