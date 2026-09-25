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

### Security

- **Varnish no longer caches authenticated static assets** (#85). The VCL's
  static-extension rule ran before its `Authorization` check, so a
  bearer-authenticated `GET /private/report.png` was cached and served to
  every later anonymous request for that URL. `Authorization` now passes
  before any cacheable rule. Re-copy `deploy/varnish/default.vcl` to
  `/etc/varnish/` and `systemctl reload varnish` to pick it up.

### Fixed

- **`install.sh` shipped a stale VCL** (#85): its embedded copy lacked the
  `PURGE` handler, per-service object tagging, session partitioning, the
  TTL/grace/keep headers, and the `no-store` static-asset override (#11), so
  Purge, session-aware caching and Cache tuning silently did nothing on
  scripted installs. The heredoc is now byte-identical to
  `deploy/varnish/default.vcl`, enforced by `TestInstallVCLMatchesDefault`.
  Re-running the installer rewrites `/etc/varnish/default.vcl`.

### Added

- **Cache HIT/MISS/PASS per request** (#85). The WAF records Varnish's
  `X-Cache` verdict for cache-routed services in a new `requests.cache_status`
  column, shows it next to the duration in the log detail modal, and exports
  `coraza_cache_results_total{app,result}` for hit-ratio dashboards. The VCL
  now reports `PASS` (auth/session/non-GET, hit-for-miss) separately from `MISS`.
- **Path-prefix cache purge** (#85). The Purge form on a service's Cache tab
  takes an optional path (e.g. `/blog/`), and `POST /api/v1/services/:id/purge`
  (body `{"path": "/blog/"}`, optional) does the same for deploy pipelines.
  The path is the client-facing one; the service's routing prefix and backend
  base path are applied before banning. Objects are now tagged with their URL
  (`X-Cache-Url`, stripped before delivery); objects cached by an older VCL
  only clear with a whole-service purge.
- **Cache performance card** on `/admin/services` (#85): per-service
  hits/misses/passes and hit ratio over the last 24h, plus Varnish-wide hit
  ratio, object count, memory used/total and LRU evictions from
  `varnishstat`. Evictions are flagged because every cached service shares one
  storage pool. The installer adds the WAF's service user to the `varnish`
  group so it can read the counters.

### Changed

- **Varnish normalizes query strings before hashing** (#85): tracking params
  (`utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_cid`/`mc_eid`, `_ga`, …) are
  dropped and the rest sorted, so equivalent URLs share one cache object.
- **Host is normalized in the cache key** (#85): lowercased with the port
  dropped, so `Example.com` and `example.com:443` share one object.
- **Cached services survive a Varnish outage** (#85). When the dial to
  varnishd fails, GET/HEAD fall back to the backend instead of returning 502
  and marking a healthy backend unhealthy. Non-GET/HEAD requests, which Varnish
  never caches, now skip the Varnish hop entirely.
- **Auto-purge on service change** (#85): removing a cached service, turning
  its cache off, or changing its backend, host or prefix purges its objects,
  so re-adding or re-enabling it never serves the old backend's content.

## [2.0.2] - 2026-09-23

### Added

- **AI Usage page** (`/admin/ai-usage`) showing every Jev API call the
  TypeSafe-backed ASN/hosting classifier (Settings' "AI Classification"
  card) has made — timestamp, ASN, organization, hosting verdict, input/
  output token counts, duration, and any error — plus 24h/7d call and
  token totals. The classifier previously wasn't logged anywhere and
  didn't even parse the API's `usage` field, so there was no way to see
  where TypeSafe token usage was going. Logged to a new capped
  `typesafe_calls` table (newest 2000 rows).

  Note: `classifyASN` still only caches a *successful* Jev judgment — an
  erroring call (bad key, rate limit, timeout) leaves the ASN uncached, so
  every subsequent request from that ASN re-triggers a fresh API call
  instead of the intended once-ever-per-ASN. Not changed by this release;
  now at least visible per-call via the AI Usage page's error column
  instead of only a one-line stderr log.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.2...main
[2.0.2]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.0.1...v2.0.2
