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

### Added

- Response compression, opt-in per service. Turn on **Compress responses** in a service's Cache tab (or set `compress_enabled` through the API) and Palisade compresses text responses over 1 KB (HTML, CSS, JavaScript, JSON, SVG and similar) with zstd or gzip, whichever the browser supports, when the backend didn't already compress them. Images, video, live event streams (SSE) and WebSockets pass through unchanged, streamed responses still arrive chunk by chunk, and responses carry `Vary: Accept-Encoding` so caches keep the variants apart. It doesn't need Varnish.
- Several backends per service, with load balancing. In a service's new **Backends** tab, list one backend URL per line and choose round robin or least connections. A backend that stops answering leaves the rotation, and GET and HEAD requests that hit it are retried once on another backend, so stopping one of two backends causes no failed page loads. Optionally set a health check path and interval: each backend is then checked on that path and only rejoins once it answers again. Without one, a failed backend sits out for 10 seconds before getting traffic again. Each backend's health shows on the Services page and as `palisade_backend_up` in Prometheus, and the API accepts `backends`, `lb_policy`, `health_path` and `health_interval`.

### Changed

- Palisade now keeps up to 100 idle connections open to each backend instead of Go's default of 2, so busy services reuse connections instead of opening a new TCP (and TLS) connection for most requests. In a test of 10 rounds of 20 concurrent requests, new backend connections dropped from 182 to 20.

### Security

- CI now runs govulncheck on every push and pull request, and weekly. It fails when Palisade's code reaches a known vulnerability in a dependency or in the Go standard library.
- Updated the bundled OWASP Core Rule Set from 4.0.0 (February 2024) to 4.25.0, bringing in more than a year and a half of new detections and false-positive fixes. The CRS is now a versioned dependency, so Dependabot proposes each new CRS release automatically, and a new baseline test checks on every update that common attacks are still blocked and ordinary traffic still passes.
- Builds now require Go 1.27.2 or later, which fixes 12 Go standard-library vulnerabilities reachable from Palisade (HTTP/2, `net/http`, `crypto/tls`, `html/template`, `net/textproto`).
- Updated dependencies to their latest patch releases, including libinjection-go 0.3.5 (the WAF's SQL injection and XSS detector) and `golang.org/x/net` 0.61.0.

## [2.6.0] - 2026-10-15

### Added

- HTTP/3 (QUIC), opt-in per service. Start Palisade with `--listen-h3 :443` (the installer now passes it) and allow UDP 443, then turn on **HTTP/3** in a service's TLS tab. Only those domains advertise HTTP/3 (`Alt-Svc`); HTTP/2 stays the default and fallback for everything else, including the admin UI. The full WAF pipeline runs unchanged, 0-RTT is disabled, and JA4 fingerprints from QUIC handshakes start with `q`. Also settable through the API as `http3_enabled`.

### Changed

- Redesigned the report, ban-alert and login-code emails to match the admin UI's current look (colours, Calistoga / DM Sans / JetBrains Mono). The daily report now adds an hourly traffic chart with the busiest hour marked, a breakdown of which stage blocked what, top blocked countries, IPs and WAF rules, and a comparison with the previous day. The charts are built from HTML tables, so they show up in Gmail too.

[Unreleased]: https://github.com/sinhaparth5/palisade-waf/compare/v2.6.0...main
[2.6.0]: https://github.com/sinhaparth5/palisade-waf/compare/v2.5.3...v2.6.0
