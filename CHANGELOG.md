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

## [2.4.0] - 2026-10-07

### Added

- **Live Stats view on the Logs page**, a GoAccess-style summary that replaces the Terminal tab. It shows requests, unique visitors, blocked share, 404s, 5xx and average response time; a requests-per-minute chart for the last hour (blocked in red); and top-10 panels for paths, IPs, block reasons (with rule ID), 404 paths, status codes, countries, services, browsers and operating systems. It starts from the last hour of data and updates on every request, over the same connection as the table.

### Changed

- **Live Logs is smoother and keyboard-friendly.** New rows are inserted in batches, so a traffic burst costs one repaint instead of one per request, and the table keeps the newest 500 rows so a page left open all day stays fast. **Pause now actually pauses**: new rows wait instead of shifting the rows you're reading, and a "N new · show" button adds them. The same happens when you scroll down to read. The status shows Live, Paused or Reconnecting instead of always claiming "Live stream active". Rows can be opened with Tab and Enter, and the detail modal moves focus in, keeps Tab inside, locks page scroll, and returns focus to the row on close. The Table/Stats choice is remembered for the browser session.
- **Admin pages load faster.** htmx is now deferred and pinned with an SRI hash, Chart.js loads only on the dashboard instead of blocking every page, and the unused htmx SSE extension is gone.

### Fixed

- **The Logs filter form and "Clear filters" link ignored a custom admin path** and always went to `/admin/logs`.
- **App/Status dropdowns needed two clicks to reopen** after being closed by an outside click. Dropdowns and date pickers now close with Escape, return focus to their button, and support arrow keys; the date picker follows its button on scroll and flips above it near the bottom of the screen.
- **Page scripts weren't cache-busted** on the Logs, Dashboard, Services and Settings pages, so a browser could keep running old JavaScript after an upgrade.
- **`truncate` could cut a multi-byte character in half** (it sliced bytes), showing a broken glyph in service names, paths and errors.
- **Low-contrast text on the Logs page** (durations, the format hint, green service names and 2xx codes) raised to readable contrast. The request-detail modal no longer squeezes into a broken two-column layout on phones.

### Removed

- **The Logs page Terminal tab** and its `/admin/access-log/stream` endpoint. It only connected when selected, so it missed requests and lagged the table. The on-disk access log (`--access-log`) is unchanged.

### Changed

- **`install.sh` now turns on the nginx-style access log** at `/var/log/coraza/access.log` (via `--access-log` and systemd's `LogsDirectory=`), on fresh installs and upgrades alike. GoAccess works against it out of the box: `goaccess /var/log/coraza/access.log --log-format=COMBINED`. The built-in rotation caps it at about 600 MB (100 MB × 5 backups + the live file).

### Fixed

- **Access log lines could be broken or forged by client input.** The method, URL and User-Agent were written raw, so a `"` in the User-Agent made the line unparseable for GoAccess and fail2ban, and a newline let a client write a whole fake log line — e.g. one that gets an innocent IP banned by fail2ban. These fields are now escaped the way nginx does it (`"`, `\` and non-printable bytes as `\xHH`).

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.4.0...main
[2.4.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.3.0...v2.4.0
