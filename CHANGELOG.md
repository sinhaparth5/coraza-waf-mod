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

## [2.0.0] - 2026-09-21

### Added

- **Passkey (WebAuthn) admin login** (issue #78). A phishing-resistant
  alternative to a TOTP code, accepted as a second factor alongside — not
  instead of — the existing authenticator/backup/email codes; an admin can
  register more than one (phone, laptop, security key) from the new
  "Passkeys" card on the Settings page. Only offered when the admin panel
  is actually reachable over HTTPS with a real hostname (or `localhost`) —
  WebAuthn can't work correctly on the plain-HTTP or bare-IP deployments
  this project also supports, so the option is hidden rather than shown
  broken. Uses `github.com/go-webauthn/webauthn` (pure Go, no CGO).

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.0...main
[2.0.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.9.6...v2.0.0
