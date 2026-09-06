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

- **One active admin session at a time, plus a "Registered devices" card.**
  Signing in on a new device now immediately signs the previous one out, and
  the old device is told why — its next action lands on the login screen with
  "Your account is currently being used on another device" rather than a
  silent timeout. The legitimate owner can therefore always take back an
  account someone else is sitting on.

  Settings gained a **Registered devices** card listing every session with its
  browser/OS, approximate location, IP and last-active time, the current one
  badged "This device · active now". Each other row carries one button that
  does whichever thing that row needs: a still-live device is signed out, an
  already-signed-out one is dropped from the history. "Log out all other
  devices" clears every session but your own.

  This reuses the existing `sessions` table rather than adding a devices
  table — there is one admin account, so every row already belongs to it, and
  the session token already identifies the device. Revoking marks
  `revoked_at` instead of deleting, which is what lets a signed-out device
  learn *why*, and what keeps the row as history. Sessions still stop
  authenticating after 24h; rows are now kept for 30 days.

### Changed

- **`prune` now deletes session rows at 30 days, not 24 hours.** Expiry still
  happens at 24h — an expired row simply stops authenticating — but the row
  is retained so the device history above has something to show. Logins are
  the only thing that grows this table, so it stays small.

- **Every management page now opens the same way.** IP Rules, Geo Rules,
  Services, Certificates, WAF Rules and Threat Intel each had a different
  top-of-page form: IP and Geo squeezed theirs into a multi-column grid
  beside supporting cards of very different heights, Services locked its
  wizard to half the card and left the rest empty, and Threat Intel used a
  one-off page header instead of the shared one. All six now lead with the
  shared hero and a single full-width primary card whose fields sit on one
  row ending in the submit button, with supporting panels moved underneath
  rather than alongside. The primary-action accent is the same colour on
  every page instead of four different ones.

### Fixed

- **Upgrades no longer leave the admin UI styled by the previous release's
  CSS.** The embedded stylesheet and scripts were served with no `ETag`,
  `Last-Modified` or `Cache-Control`, which lets a browser keep a cached copy
  indefinitely — so after an upgrade the new dashboard could render under the
  old stylesheet, with no error and nothing to indicate why it looked wrong.
  Asset URLs now carry a hash of the stylesheet, giving every build its own
  URLs. This was not hypothetical: it hid the layout work above during
  development while the compiled CSS plainly contained the missing classes.

- **Five admin-UI icons rendered as blank squares.** `hgi-fingerprint-01`,
  `hgi-server-stack-01`, `hgi-shield-minus`, `hgi-wifi` and
  `hgi-wifi-router-01` are not glyphs in the icon font the dashboard loads, so
  the Logs fingerprint and network rows, the "Request Blocked" panel, the
  Services page and both "Test connection" buttons were drawing empty boxes.
  A wrong icon name fails silently — nothing validates it — so each was
  checked against the font itself and replaced with a real equivalent.

## [1.8.1] - 2026-09-04

### Changed

- **Services: opt-in large JavaScript uploads.** S3-compatible `PutObject`
  requests for `.js` assets were treated as inspectable non-file bodies and
  rejected with 413 above 128 KiB. A new per-service Uploads setting streams
  JavaScript media types to the backend and permits the CRS method and
  content-type rules an S3 `PUT` needs, while retaining every other
  header-phase WAF, IP, bot, and rate-limit check.

### Removed

- **Unused `config.yaml` / `deploy/config.yaml.example`.** Nothing in the
  running server has parsed them since the move to CLI flags plus DB-backed
  settings; they only misled readers about where configuration lives.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.8.1...main
[1.8.1]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.8.0...v1.8.1
