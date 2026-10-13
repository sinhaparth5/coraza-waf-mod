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

### Changed

- The product is now named **Palisade** (was "Coraza WAF Mod"): admin UI, login and challenge pages, emails, webhook footers, TOTP/passkey display names, the `Server` response header, TLS self-signed CN and systemd unit descriptions. Built on OWASP Coraza.
- `install.sh` now installs under the `palisade` name (binary, systemd service and prune timer, service user, `/var/lib/palisade`, `/etc/palisade`, `/var/log/palisade`) and **migrates an existing `coraza-waf-mod` install automatically** when you re-run it: data, database, certs and the encryption key are moved, not recreated. The repo, release asset names, installer URL and `coraza_*` metric names are unchanged. Docker image entrypoint is now `/palisade`.
- Prometheus metrics are renamed from `coraza_*` to `palisade_*` (update dashboards and alerts), the `X-WAF-Engine` header now reads `Palisade`, the Go module is `palisade`, the cluster blocklist channel is `palisade:ipblocklist:reload` (mixed-version clusters won't sync blocklist reloads during a rolling upgrade), backups download as `palisade-YYYY-MM-DD.db`, and the threat-intel User-Agent is `palisade/threat-intel`.
- Admin UI redesigned as a field-notes notebook: warm paper and ink palette (with a dark mode), Calistoga/DM Sans/JetBrains Mono/Caveat type, green = allowed, red = blocked, lime = highlight.

## [2.4.1] - 2026-10-13

### Fixed

- `install.sh` hung (or exited silently) right after the database prompt when run as `curl | bash`: `exec < /dev/tty` replaced the pipe bash was reading the script from. Stdin is now saved and restored around the prompts.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.4.1...main
[2.4.1]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.4.0...v2.4.1
