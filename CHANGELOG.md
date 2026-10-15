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

## [2.5.2] - 2026-10-15

### Changed

- The installer's version pin is now `PALISADE_VERSION` (e.g. `curl -fsSL ... | sudo PALISADE_VERSION=v2.5.1 bash`).
- The installer only installs v2.5.1 and later: it no longer migrates a pre-2.5.0 `coraza-waf-mod` install, falls back to the old `coraza-waf-mod-*` release asset names, or reads `CORAZA_VERSION`.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.2...main
[2.5.2]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.1...v2.5.2
