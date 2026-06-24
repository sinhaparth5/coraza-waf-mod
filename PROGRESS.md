# coraza-waf-mod — Build Progress

A single-binary Go WAF + reverse proxy with embedded Coraza, SQLite storage, and an HTMX/Tailwind dashboard.

---

## Architecture

```
[Client] → [Coraza WAF + Proxy (Echo)] → [Backend App(s)]
                     ↕
               [SQLite DB]
                     ↕
              [HTMX/Tailwind UI]
```

**Tech stack:** Go · Echo · Coraza v3 · SQLite (modernc, pure Go) · GeoIP2 · HTMX · Tailwind CSS

---

## Phases

### Phase 0 — Project Setup ✅ COMPLETE
- [x] Go module initialised (`go.mod`)
- [x] Core dependencies added (Coraza v3, Echo v4, goccy/go-yaml)
- [x] Folder structure created (`config/`, `waf/`, `proxy/`, `geo/`, `storage/`, `ui/`)
- [x] `config.yaml` skeleton

### Phase 1 — Core Reverse Proxy + Coraza ✅ COMPLETE
- [x] Echo server boots and listens
- [x] Single-backend reverse proxy working (tested: 200 proxied through)
- [x] Coraza WAF engine initialised with **OWASP CRS loaded** (`waf/engine.go`, embedded via `coraza-coreruleset`)
- [x] Every request runs through a Coraza transaction (`waf/engine.go`)
- [x] Interrupted requests (blocked by WAF) return 403
- [x] Real client IP extracted: `CF-Connecting-IP` → `X-Forwarded-For` → `X-Real-IP`
- [x] TLS support: Let's Encrypt auto (`mode: auto`) + custom cert (`mode: custom`) + plain HTTP (`mode: off`)
- [x] Native CRS exploit coverage confirmed end-to-end (SQLi, XSS, RCE, path traversal, restricted file access, scanner UA detection) — see Decision Log 2026-06-24 for a directive-ordering bug that silently kept the engine in detection-only mode until fixed

### Phase 2 — Multi-App Support ✅ COMPLETE
- [x] Services (formerly config.yaml `apps:`) now live in SQLite, managed entirely from the admin UI — `storage.Service` + CRUD, a `services.Registry` (mutex-protected, rebuilds reverse proxies on `Reload()`)
- [x] One-time migration on first startup: existing `config.yaml` apps: entries are copied into the `services` table (`db.MigrateConfigApps`, guarded by a `meta` flag so it never double-runs); `config.yaml`'s `apps:` list is ignored after that
- [x] Route by `Host` header (virtual hosting)
- [x] Route by path prefix
- [x] Services page: 4-step add wizard (Name → Match rule → Backend URL → Review), list + remove table, no restart needed — `registry.Reload(db)` picks up changes live
- [x] Backend reachability check: `services.Probe()` rejects an add if the backend doesn't respond (no DB write, one-shot check only). Ongoing health is **passive** (no background prober, no synthetic requests) — a service flips red the instant a real proxied request fails (`ReverseProxy.ErrorHandler`) and green on the next real request that succeeds (`ModifyResponse`), same approach as nginx/HAProxy/Envoy passive health checks and how SafeLine avoids logging synthetic probe traffic. Services page shows a live red/green/grey dot per row, polled every 15s. Tradeoff: a fully idle service with zero real traffic stays "unknown" until something actually hits it
- [x] Route matching: path-Prefix rules win over a host-wide catch-all (longest prefix wins), mirroring nginx's location-vs-server_name precedence — needed so a Prefix-routed service isn't shadowed by an earlier Host-routed service on the same host
- [x] Prefix-matched services have their matched prefix stripped from the path before forwarding to the backend (Host-matched services are untouched) — the backend doesn't know what prefix the proxy used to reach it (e.g. a Vite/React-Router dev server mounted at `/`), same as nginx's `location /foo/ { proxy_pass http://backend/; }`. Admin logs still show the original client-facing path
- [x] Per-service TLS (host-matched services only — SNI needs a domain): admin can upload a cert+key PEM pair (private key written to disk under `certs/services/<name>/`, `0600`, never stored in the DB) or enable on-demand Let's Encrypt issuance per service; SNI dispatch picks custom cert → autocert → legacy global fallback. "TLS" column + modal on the Services page (`POST /admin/services/tls/{upload,auto,clear}`)
- [ ] Hot-reload config on SIGHUP (Phase 6, now only relevant to TLS/WAF/admin config, not apps)

### Phase 3 — Structured Logging to SQLite ✅ COMPLETE
- [x] SQLite DB initialised (`modernc.org/sqlite`, WAL mode)
- [x] `requests` log table: `ts, app_name, real_ip, country, method, host, path, status, blocked, rule_id, action, user_agent, duration_ms`
- [x] Every proxied request logged (including status code capture via wrapped ResponseWriter)
- [x] Blocked requests flagged with WAF rule_id + action
- [x] Query helpers: `GetStats()`, `ListRequests()`, `ListRequestsFiltered()` (date/app/status filters + pagination), `GetHourlyTraffic()`, `GetTopBlockedCountries()`, `CountBlockedSince()`
- [x] Automatic log retention: `db.log_retention_days` (default 30, -1 = forever), pruned daily by a background goroutine

### Phase 4 — IP Blocking + Geo Blocking ✅ COMPLETE
**IP Blocking**
- [x] Global + per-app IP blacklist / whitelist (`blocklist/ip.go`)
- [x] In-memory map synced from SQLite on startup (`Reload()`)
- [x] `ip_rules` table with CRUD methods in storage

**Geo Blocking**
- [x] MaxMind GeoLite2-Country `.mmdb` loaded via `geoip2-golang` (`geo/geoip.go`)
- [x] Per-app + global country allow/block rules in `geo_rules` table
- [x] Lookup on every request; 403 with country code in response
- [x] Check order: IP block → Geo block → WAF (fastest checks first)

### Phase 5 — Web UI Dashboard ✅ COMPLETE
- [x] Admin routes protected with HTTP Basic Auth
- [x] Light theme redesign ("Coraza WAF Mod" branding): top nav, card-based layout, green/navy palette
- [x] Dashboard: real stat cards (today/all-time totals + blocked), real Chart.js graphs (hourly traffic, top blocked countries via `/admin/api/traffic` + `/admin/api/threats`), recent requests table, right sidebar with top threats + WAF status card
- [x] Notification bell: real blocked-count badge + dropdown of actual recent blocks (`/admin/api/notifications`), persisted read-state (`meta` table, `NotificationsSeenAt`/`MarkNotificationsSeen`) so the badge only counts genuinely new blocks and clears via "Mark all as read" instead of resetting on every reload
- [x] Logs page: DB-backed (survives restarts), filter bar (date range with local→UTC conversion, app, status class incl. "Blocked only"), pagination, wider column spacing; SSE live-tail only active when unfiltered
- [x] IP Rules page: add/remove block/allow per IP, global or per-app, HTMX in-place updates
- [x] Geo Rules page: add/remove country block/allow rules, HTMX in-place updates
- [x] Country flag CSS (flag-icons) from ISO code; country shown in all log views
- [x] Templates embedded in binary via embed.FS (single self-contained binary)
- [x] IBM Plex Sans typeface; darkened muted-grey text (#94A3B8 → #64748B) for readability
- [x] All inline `<script>` blocks and `onclick`/`onfocus`/`onblur` attributes removed; JS lives in `static/js/src/*.js`, minified to `static/js/dist/*.min.js` via a pure-Go build step (`tools/minify`, `tdewolff/minify`), embedded and served at `/admin/static/js/`. **Run `make build` (not bare `go build`) after editing any source `.js` file** — see Makefile / `//go:generate` in `main.go`
- [x] Notification badge updates live via SSE (`/admin/api/notifications/stream`, reusing the existing `LogBroadcaster`) — no page reload needed to see new blocks
- [ ] Icon set: current icons are Hugeicons via CDN; user wants to swap specific icons for better ones — pending icon-by-icon list (see chat, not yet finalized)

### Phase 6 — Polish & Production (in progress)
- [x] `Server: Coraza WAF Mod` response header on every response (blocked or proxied), overriding whatever the backend sends
- [x] Native binary distribution (no Docker, by explicit choice): `make dist` cross-compiles stripped `linux/amd64` + `linux/arm64` binaries (CGO-free, since `modernc.org/sqlite` needs no C toolchain to cross-compile), `make checksums` produces `dist/checksums.txt`. `deploy/coraza-waf-mod.service` is a hardened systemd unit (dedicated non-root system user, `CAP_NET_BIND_SERVICE` instead of root for ports 80/443, `ProtectSystem=full`/`PrivateTmp`/`NoNewPrivileges`). `deploy/install.sh` is a self-contained one-line `curl | sudo bash` installer: detects arch, downloads + verifies SHA256, creates the system user and `/etc/coraza-waf-mod` + `/var/lib/coraza-waf-mod`, generates a random admin password on first install (printed once, never a hardcoded default), writes the systemd unit, and starts the service. **`BASE_URL` in `install.sh` is a placeholder** — needs to point at wherever release assets actually get published (GitLab Release, package registry, etc.) before the one-liner works for real users
- [x] Bounded backend transport timeouts (`services/registry.go`'s `backendTransport`: 5s dial, 10s response-header) — Go's default transport has *no* response-header timeout and a 30s dial timeout, so a dead/unresponsive backend (including the implicit fallback-to-first-service path for unmatched requests like `/favicon.ico`) could hang a proxied request for 30s+, which then queues up the browser's limited per-origin connections and makes unrelated admin page navigations appear stuck for tens of seconds
- [x] Prometheus metrics endpoint: new `metrics` package (`metrics/metrics.go`), served at `{admin.path}/metrics` (e.g. `/admin/metrics`) behind the same Basic Auth as the rest of the admin UI — no separate auth model needed since Prometheus scrape configs support `basic_auth` natively. Exposes `coraza_http_requests_total{app,status}` (counter), `coraza_http_request_duration_seconds{app}` (histogram), `coraza_ip_blocked_total{app}`, `coraza_geo_blocked_total{app,country}`, `coraza_waf_blocked_total{app,action}` (all incremented at the exact decision point in `proxy/handler.go`'s `Handle()`/`writeLog()`), plus `coraza_log_queue_depth` and `coraza_services_total` as `GaugeFunc`s that read live state (`storage.DB.QueueDepth()`, `services.Registry.List()`) on every scrape rather than via a polling goroutine — consistent with this project's existing passive-observation pattern (see Phase 2's health checks). Standard Go runtime/process collectors (`go_*`, `process_*`) are included automatically by `client_golang` v1.23's default registry. Verified end-to-end with a throwaway test hitting the real `metrics.Handler()` and asserting on the exposition-format output, then deleted.
- [ ] Rate limiting (in-process token bucket; superseded by Redis-backed rate limiting in Phase 8)
- [ ] Config hot-reload (SIGHUP)
- [ ] `Dockerfile` + `docker-compose.yml` example
- [ ] DB backup / restore endpoint
- [ ] End-to-end test suite with simulated Cloudflare headers + real attack payloads (currently verified ad hoc via `go test` against the real Coraza engine — see Decision Log)

### Phase 7 — Advanced Anti-Bot Protection (not started)
- [ ] JA3/JA4 TLS fingerprinting: inspect the TLS handshake (cipher suites, extensions order) and flag/drop clients whose fingerprint doesn't match their claimed User-Agent (e.g. "Chrome" UA with a Python/Go TLS stack)
- [ ] Cryptographic JS challenge: serve a background math-puzzle interstitial to suspicious requests to filter out headless scrapers while real browsers pass through transparently
- [ ] Behavioral rate limiting: track per-client telemetry in Redis; flag bots that hit API paths uniformly without ever fetching static assets (images/CSS/JS)
- [ ] CAPTCHA fallback: integrate an upstream provider (Cloudflare Turnstile or reCAPTCHA) as a challenge when the anomaly score crosses a high threshold

### Phase 8 — Redis-Backed Rate Limiting & Traffic Management (not started)
- [ ] Redis-backed rate limiter for login endpoints and heavy DB-backed routes (brute-force + L7 volumetric abuse protection)
- [ ] Per-IP / per-route configurable limits in `config.yaml`
- [ ] Supersedes the in-process token-bucket placeholder noted in Phase 6

### Phase 9 — Dynamic Virtual Patching (not started)
- [ ] Admin UI to toggle individual CRS rule IDs on/off (handle false positives without editing config files or restarting)
- [ ] Persist rule-toggle state in SQLite, applied at WAF init / hot-reload time
- [ ] Surface which rule IDs fired most often (from existing `rule_id` logging) to make toggling decisions data-driven

### Phase 10 — Threat Intel Sync Pipeline (not started)
- [ ] Background worker that periodically pulls known-malicious IP lists (Tor exit nodes, Spamhaus, AbuseIPDB, etc.)
- [ ] Feed pulled IPs into the existing `ip_rules` blocklist mechanism (reuse Phase 4 infrastructure)
- [ ] Configurable refresh interval + source list in `config.yaml`

### Phase 11 — Structured Audit Logging / SIEM Export (not started)
- [ ] Export Coraza's full JSON audit log detail (not just the summary fields currently in `requests`) for blocked transactions
- [ ] Pluggable export sink (webhook / file / syslog) so users can forward to an external SIEM
- [ ] Dashboard view of full audit detail per blocked request (matched rule chain, not just final rule ID)

---

## Folder Structure (target)

```
coraza-waf-mod/
├── main.go
├── config/
│   └── config.go          # YAML loader + structs
├── waf/
│   └── engine.go          # Coraza wrapper + real IP injection
├── proxy/
│   └── handler.go         # Reverse proxy logic + WAF integration
├── geo/
│   └── geoip.go           # MaxMind GeoLite2 wrapper
├── storage/
│   └── db.go              # SQLite models (logs, bans, geo rules, services)
├── services/
│   └── registry.go        # DB-backed service registry + reverse proxies, hot-reloadable
├── ui/
│   ├── handlers.go        # Echo handlers for dashboard pages
│   └── templates/         # HTML + HTMX templates
├── rules/                 # OWASP CRS rule files
├── static/                # Tailwind CSS, any JS
├── config.yaml
├── go.mod
├── go.sum
└── PROGRESS.md
```

---

## Current Status

**Phases 0–5 complete.** Core proxy, WAF (with confirmed-working CRS blocking), multi-app routing, SQLite logging with retention, IP/geo blocking, and the full admin dashboard (real data, real charts, real notifications, filterable logs) are all in place and verified.

**Phase 6 in progress.** `Server` header done; rate limiting, hot-reload, Docker, backups, and metrics still open.

**Next up:** working phase-by-phase through Phases 7–11 (anti-bot protection, Redis rate limiting, dynamic virtual patching, threat intel sync, SIEM export) — added 2026-06-24 as a roadmap, not yet implemented.

---

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-06-23 | Pure-Go SQLite (`modernc.org/sqlite`) over `mattn/go-sqlite3` | No CGO needed; single binary deployment |
| 2026-06-23 | Echo over Gin/Fiber | Good proxy middleware support + familiar API |
| 2026-06-23 | HTMX + Tailwind over React/Vue | No build step; server-rendered; simpler ops |
| 2026-06-24 | Log retention default 30 days, configurable via `db.log_retention_days` | Balance between investigation history and unbounded SQLite growth |
| 2026-06-24 | Dashboard charts use Chart.js via CDN, not hand-rolled SVG | Animated/interactive charts with tooltips, matching the redesigned UI's polish level |
| 2026-06-24 | Never use SQLite `date()`/`strftime()` on the `requests.ts` column; bucket by date/hour in Go instead | `modernc.org/sqlite` stores `time.Time` using Go's `.String()` format (`"... +0000 UTC"`), which SQLite's native date functions can't parse and silently return NULL for. Plain `>=`/`<=` comparisons against `ts` work correctly and were verified against real data |
| 2026-06-24 | `waf/engine.go` directives: `Include`s first, our own `Sec*` overrides last | `@coraza.conf-recommended` sets `SecRuleEngine DetectionOnly` as a safe default; since directives apply in sequence, our `SecRuleEngine On` was being set *before* that include and silently clobbered back to detection-only — the WAF scored every match correctly but never actually blocked anything until this was found and fixed |
| 2026-06-24 | Verify WAF/storage behavior with throwaway `go test` files against real Coraza transactions / the real `waf.db`, not by starting the server | User does not want the server started to smoke-test changes; `go test` against the actual engine/storage code gives the same ground truth without violating that |
| 2026-06-24 | Apps move from static `config.yaml` `apps:` list to a DB-backed `services` table + admin UI wizard, fully replacing the YAML list (one-time migration on first startup) | User wants to add/edit/remove backends without restarting or hand-editing YAML; DB-only (not coexisting with YAML) avoids two sources of truth for routing |
| 2026-06-24 | Service add wizard uses manual JS validation (`.value.trim()`) instead of HTML5 `required`/`checkValidity()`, with `novalidate` on the form | Hidden wizard steps (`display:none`) with `required` inputs are still subject to native constraint validation per spec, but can't be focused for the validation bubble — Chrome silently blocks the submit and logs "is not focusable" with no visible error to the user |
| 2026-06-24 | Backend reachability: any HTTP response (even 4xx/5xx) counts as "reachable" in `services.Probe`; only a dial/timeout failure counts as unreachable | Checking connectivity, not correctness — a backend with no route at `/` is still a legitimate, reachable backend |
| 2026-06-24 | Replaced the active 30s health-poll loop with passive health tracking from real proxied traffic (`ReverseProxy.ErrorHandler`/`ModifyResponse`) | User asked how SafeLine detects downtime without active probes or logging synthetic requests — passive checks (used by nginx/HAProxy/Envoy) give the same instant detection with zero added requests; `services.Probe()` is kept only for the one-shot add-time reachability check |
| 2026-06-24 | Private keys for per-service custom TLS certs are written to disk (`certs/services/<name>/`, `0600`) rather than stored in `waf.db` | `waf.db` was already tracked in git with no `.gitignore`; keeping key material out of the SQLite file (now gitignored) avoids ever committing private keys |
| 2026-06-24 | Per-service TLS uses one unified `tls.Config.GetCertificate` (custom cert by SNI → autocert if host is in per-service "auto" hosts or legacy domain list → static legacy fallback) instead of the old global single-cert switch | Needed real SNI-based per-domain cert selection now that services (with their own Host domains) are added dynamically; keeps backward compat with the existing global `tls.mode: auto\|custom` config |
| 2026-06-24 | All per-service reverse proxies now share one `http.Transport` with a 5s dial timeout and 10s response-header timeout, instead of Go's default (30s dial, *no* response-header timeout) | User reported admin pages randomly taking 23-52s to load when navigating between routes; root cause was the `services` table's only service (`example`, backend `localhost:3000`) doubling as `Match()`'s fallback target for any unmatched request (e.g. browser's automatic `/favicon.ico` fetch) — when that backend was down, the proxy hung on the dial/response for up to 30s with zero timeout on the response side, and that stuck connection ate one of the browser's ~6 per-origin connection slots, queuing subsequent real page navigations behind it. Verified via a throwaway `services` package test: a backend that accepts a TCP connection but never responds now fails in ~10s instead of hanging indefinitely |
| 2026-06-24 | `Registry.Match()` checks all services' path Prefix rules (longest wins) before falling back to an exact Host match | User added a second service with a path Prefix on the same host as an existing Host-wide catch-all service; the catch-all always won since it was checked first in list order, regardless of how specific the other service's Prefix was — same precedence nginx uses (location blocks beat a bare server_name default) |
| 2026-06-24 | Prefix-matched services get their matched prefix stripped from `r.URL.Path` before `rp.ServeHTTP`, restored before logging | A proxied React-Router/Vite dev server returned its own client-side 404 for `/test-app` because it was mounted at `/` and had no route registered for the prefix the proxy used to find it — same fix as nginx's `location /foo/ { proxy_pass http://backend/; }`. Host-matched services keep the path untouched (virtual hosting, not path routing) |
| 2026-06-24 | (Superseded same day, see below) `storage.Open` initially called `conn.SetMaxOpenConns(1)` and set `PRAGMA busy_timeout=5000` via a post-open `Exec` | First attempt at fixing `SQLITE_BUSY "database is locked"` under concurrent proxied writes. Worked for the immediate symptom, but capping the pool at 1 connection meant every read *and* write — including request logging done synchronously on the hot path in `proxy/handler.go` — now serialized through a single connection, turning a burst of parallel requests (e.g. one dev-server page load) into a queued backlog that looked just like the earlier "stuck page" bug, with multi-minute degradation under load |
| 2026-06-24 | Replaced with: PRAGMAs passed via DSN (`?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)`), pool un-capped to `SetMaxOpenConns(8)`, plus async request logging via a buffered channel + dedicated worker goroutine (`storage.DB.logQueue`/`runLogWorker`/`QueueRequest`) | `modernc.org/sqlite` applies `_pragma` DSN query params to *every* new physical connection as it's opened (confirmed in driver source: `Driver.Open` → `newConn` → `applyQueryParams`), unlike a one-shot post-open `Exec` which only configures whichever single connection runs it — so the pool can now safely hold multiple connections while every one of them still has `busy_timeout` set. Un-capping the pool lets WAL-mode concurrent reads (dashboard, logs page) avoid queuing behind writes. Moving request logging off the hot path (`proxy/handler.go`'s `writeLog` now calls `db.QueueRequest`, fire-and-forget) means a slow or contended DB write can never hold open the HTTP connection of the request that triggered it — the actual root cause of the recurring slowdown, not just the `SQLITE_BUSY` error message. `DB.Close()` drains the queue before closing the connection so no entries are lost on shutdown. Verified with throwaway tests: 200 concurrent `QueueRequest` calls return in under 1ms total (not blocking on the DB) and all 200 rows are confirmed written by the worker; a second test confirms `Close()` drains a still-pending queue rather than dropping it |
| 2026-06-24 | Added `idx_requests_blocked_ts` composite index on `requests(blocked, ts)` | `GetTopBlockedCountries`/`CountBlockedSince` filter on `blocked = 1 AND ts >= ?`; SQLite can only use one single-column index per simple query, so the existing separate `idx_requests_blocked` and `idx_requests_ts` indexes couldn't both apply to this pattern |
| 2026-06-24 | `proxy.responseWriter` now implements `Hijack()` and `Flush()`, passing through to the underlying `http.ResponseWriter` | WebSocket upgrades (e.g. a Vite dev server's HMR client) failed with "can't switch protocols using non-Hijacker ResponseWriter" — wrapping `http.ResponseWriter` in a struct to capture the status code for logging hides any capability not part of the `http.ResponseWriter` interface itself (Go doesn't promote it just because the underlying concrete value supports it), and `httputil.ReverseProxy` requires `http.Hijacker` to upgrade a connection. Verified with a throwaway test driving a real 101 Switching Protocols handshake end-to-end through `proxy.Handler` |
