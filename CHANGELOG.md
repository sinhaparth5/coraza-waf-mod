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

### Fixed

- **Five admin-UI icons rendered as blank squares.** `hgi-fingerprint-01`,
  `hgi-server-stack-01`, `hgi-shield-minus`, `hgi-wifi` and
  `hgi-wifi-router-01` are not glyphs in the icon font the dashboard loads, so
  the Logs fingerprint and network rows, the "Request Blocked" panel, the
  Services page and both "Test connection" buttons were drawing empty boxes.
  A wrong icon name fails silently — nothing validates it — so each was
  checked against the font itself and replaced with a real equivalent.

## [1.8.0] - 2026-08-19

### Changed

- **Services: opt-in large JavaScript uploads.** S3-compatible `PutObject`
  requests for `.js` assets were treated as inspectable non-file bodies and
  rejected with 413 above 128 KiB. A new per-service Uploads setting streams
  JavaScript media types to the backend and permits the CRS method/content-type
  rules required by S3 `PUT`, while retaining other header-phase WAF, IP, bot,
  and rate-limit checks.

- **Management pages now use balanced, top-first layouts.** IP Rules, Geo
  Rules, WAF Rules, Services, Certificates, and Threat Intel place their
  important controls above full-width results instead of stretching a tall
  control stack beside a short list. Settings shares the refreshed visual
  hierarchy, while responsive grids keep the same forms, HTMX targets, data,
  and actions on mobile and desktop.
- **New security artwork and denser visual system.** Two optimized, locally
  embedded WebP illustrations add restrained navy, cyan, and emerald accents
  to management surfaces. Card headers and icons use clearer hierarchy and
  the existing reduced-motion-aware entrance effects. The dashboard's
  “At a glance” tiles are compact, equal-height, and two-up on phones, while
  the notification tray now opens inside the visible viewport.

### Fixed

- **A file upload no longer costs a minute of latency and gigabytes of resident
  memory** (MonoBucket issue #19). A 3.5 MiB `PUT` of a PDF through the proxy
  measured at **52 seconds and 4.4 GiB of allocations, peaking at 2.4 GiB of
  heap**, and was then refused as an attack. It now measures at **1 ms and
  1 MiB**.

  The cause was a collaboration between Coraza and CRS that neither side
  intends. Coraza infers a request-body processor for exactly two content types
  — `x-www-form-urlencoded` and `multipart/form-data` — and leaves it unset for
  everything else. CRS rule 901340 matches "processor is not
  URLENCODED|MULTIPART|XML|JSON" and fires `ctl:forceRequestBodyVariable=On`,
  and Coraza answers that flag by defaulting the processor to `URLENCODED`. So
  every PDF, image, video and S3 payload was parsed as an HTML form: 3.5 MiB of
  binary carries an `&` roughly every 256 bytes, producing ~14,000 junk `ARGS`
  entries, and CRS then ran ~200 rules across all of them with every
  intermediate transformation cached as a full string copy for the length of
  the phase. Binary data also scores 830 against CRS's XSS/SQLi/RCE detectors,
  so the request was denied at the end of that minute anyway.

  `Engine.Check` now decides from the declared `Content-Type` whether a body is
  worth inspecting at all. Form, multipart, JSON, XML and `text/*` bodies are
  inspected as before; an absent `Content-Type` is inspected too, since
  otherwise omitting the header would be the bypass. Everything else streams to
  the backend without this process reading a byte of it — which also means a
  large upload is no longer buffered here on its way through.

  This is a real trade rather than a free win, and worth stating plainly: a
  client that declares `application/octet-stream` on a payload the backend then
  parses as a form has evaded body inspection. CRS 920420 still flags content
  types outside its allow-list at PL1, so the declaration is not free, and the
  behaviour being replaced was not "these uploads are inspected" — it was
  "these uploads take a minute and are then rejected as an attack".

- **`SecRequestBodyNoFilesLimit` is now actually enforced.** The engine set
  `SecRequestBodyNoFilesLimit 131072`, which reads like a 128 KiB cap on
  non-file bodies. Coraza parses that directive and ignores it (see the TODO in
  `internal/corazawaf/waf.go` referencing corazawaf/coraza#896 — which is why
  `coraza.conf-recommended` ships the line commented out with a note saying
  so), so the only limit ever in force was the 12.5 MiB `SecRequestBodyLimit`.
  The dead directive is gone and the limit is applied in `Check` instead: a
  non-multipart body past 128 KiB is refused with 413, matching the
  `SecRequestBodyLimitAction Reject` posture the multipart path already gets
  from Coraza. Multipart keeps the 12.5 MiB limit, because Coraza routes file
  parts to `FILES` rather than `ARGS` and a 3.5 MiB multipart upload measures
  at 28 ms — file uploads were never the expensive shape.

  **This can reject requests that previously succeeded**: a JSON or form body
  between 128 KiB and 12.5 MiB now gets a 413. That is the CRS-recommended
  posture and the number this file already claimed to enforce, but an API
  posting large JSON bodies will notice. Cost is the reason for the cap —
  measured against CRS 4, a non-multipart body costs ~2.8s and 800 MiB at
  128 KiB, and ~30s and 6.4 GiB at 1 MiB, whatever the bytes contain. Making
  the limit an admin-configurable setting is the natural follow-up.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.8.0...main
[1.8.0]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.7.0...v1.8.0
