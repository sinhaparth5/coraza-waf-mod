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

## [2.5.1] - 2026-10-15

### Added

- Codecov coverage reporting in CI. The unit run uses `-coverpkg=./...` so code is credited wherever it executes, the MySQL/Postgres storage runs upload as separate flags and merge in, and a Redis service backs the previously untested Redis rate-limit and cluster-sync paths. README carries a coverage badge. Test results are uploaded too (via `gotestsum` JUnit output) for Codecov Test Analytics. Coverage is about 90%, up from 56%; new tests cover every admin UI route through the real middleware stack, the storage CRUD/query layer on all three database backends, and the previously untested config, bot, JA3, blocklist, threat-intel, metrics and passkey packages.

### Changed

- The GitHub repository is now `sinhaparth5/palisade-waf` (old URLs redirect). Release assets are published as `palisade-waf-linux-amd64`/`-arm64`/`-windows-amd64.exe`, Docker images as `ghcr.io/sinhaparth5/palisade-waf` and `palisade-waf` on Docker Hub, and the installer moved to `https://waf-install.astrareconslabs.com/palisade-waf/install.sh`. The new installer still installs pre-rename versions pinned with `CORAZA_VERSION`. Images already published under `coraza-waf-mod` stay there and get no new tags.

### Fixed

- Saving the Let's Encrypt contact email from the Services page left the email dialog open: the handler's `acme-email-saved` event was overwritten by the `tls-saved` event sent right after it, so the dialog never received it. Both events are now sent.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.1...main
[2.5.1]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.0...v2.5.1
