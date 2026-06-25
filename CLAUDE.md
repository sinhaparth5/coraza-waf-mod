# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-binary Go WAF + reverse proxy: embedded Coraza v3 (OWASP CRS) for request inspection, Echo for HTTP/routing, SQLite (modernc, pure Go, no CGO) for all storage, and an HTMX + Tailwind admin dashboard served from the same binary.

```
[Client] → [Coraza WAF + Proxy (Echo)] → [Backend App(s)]
                     ↕
               [SQLite DB]
                     ↕
              [HTMX/Tailwind UI]
```

## Commands

```bash
make build       # go generate (minifies JS) + go build -> ./coraza-waf-mod
make run          # build + run
make test         # go test ./...
make clean        # remove binary, minified JS, dist/
make dist         # cross-compile linux/amd64 + linux/arm64 + windows/amd64 release binaries (CGO_ENABLED=0)
make checksums    # sha256sum dist/* -> dist/checksums.txt
```

Run a single test: `go test ./proxy/ -run TestName -v` (substitute the package).

**Never run `go build` directly after editing JS** — `go:generate` (which runs the JS minifier in `tools/minify`) only fires via `make build`/`make dist`, not bare `go build`. If you must, run `go generate ./...` first.

Do not start the server (`go run .`, `make run`, etc.) without the user explicitly asking each time — verify changes with throwaway `go test` files instead, and delete them once they pass.

## Architecture

**Request flow** (`proxy/handler.go`, single `Handle` method, in order): IP blocklist check → rate limit check → geo blocklist check → Coraza WAF inspection → reverse-proxy to the matched backend. Every stage logs to SQLite via a fire-and-forget queue, never blocking the hot path. Every response (blocked or proxied) gets its `Server` header forced to `Coraza WAF Mod`, overwriting whatever the backend sent — set independently in both `proxy/handler.go` and `services/registry.go`'s `ModifyResponse` since proxied responses pass through the latter.

Request logs are not kept forever, but pruning is **not** automatic inside the running server — `coraza-waf-mod prune [config.yaml]` (`runPruneOnly` in `main.go`) is a separate one-shot CLI mode that opens the DB, deletes rows older than `db.log_retention_days` (default 30, set in `config/config.go`; `<= 0` disables pruning), and exits without starting the WAF/proxy/admin UI. It's meant to be invoked by an external scheduler — cron, or the systemd timer in `deploy/coraza-waf-mod-prune.{service,timer}` — so a multi-second delete never shares the live process's DB connection pool with request traffic. `storage.DB.PruneOldRequests` itself deletes in batches of `pruneBatchSize` (2000) rows with a short pause between batches rather than one giant `DELETE`, since SQLite holds its single process-wide write lock for the full duration of an unbatched delete.

**Services are DB-backed, not config-driven.** `config.yaml`'s `apps:` list is only read once on first-ever startup (`storage.MigrateConfigApps`) to seed the `services` table; after that, `/admin/services` in the UI is the sole source of truth. `services.Registry` (`services/registry.go`) holds the current service list plus one pre-built `httputil.ReverseProxy` per service behind a `sync.RWMutex`, and is rebuilt wholesale via `Reload(db)` whenever a service is added/edited/removed — no restart needed. All proxies share one `backendTransport` with explicit dial (5s) and response-header (10s) timeouts, since Go's default transport has no upper bound on waiting for a backend and will otherwise stall browser connection slots.

**Routing precedence** in `Registry.Match(host, path)`: all Prefix-matched services are checked first (longest prefix wins), then Host matches — mirroring nginx's `location` blocks beating `server_name` defaults. For prefix-matched services, `proxy/handler.go`'s `Handle()` strips the matched prefix from the request path before proxying (restored before logging, so the admin UI shows the real client path) — like `proxy_pass http://backend/` in nginx. Host-matched services are passed through untouched (virtual hosting).

**Health is passive, not polled.** There is no background health-check loop; `Registry.markHealth` is driven entirely by real proxied traffic outcomes via each `ReverseProxy`'s `ErrorHandler` (failure → unhealthy) and `ModifyResponse` (response received → healthy) hooks. The one exception is `services.Probe()`, a single one-shot reachability GET run only when a service is first added through the UI, to reject obviously-dead backends before they're saved.

**TLS**: `tls.mode` in config.yaml is `off` (default) / `auto` (Let's Encrypt via `autocert`) / `custom` (static cert+key files), handled by `startAutoTLS`/`startCustomTLS` in `main.go`. Independently, each service can have its own TLS via the admin UI ("Manage" modal per row): an uploaded custom cert, or per-service auto-issue. `Registry.GetCertificateFunc` resolves certs by SNI in priority order: per-service custom cert → per-service/legacy autocert (if host is allowed by `Registry.HostPolicy()` unioned with the legacy static domain list) → global fallback. Uploaded private keys are stored on disk under `certs/services/<name>/` (mode 0600), not in `waf.db`.

**WAF engine** (`waf/engine.go`): directive order matters and has bitten this project before — `@coraza.conf-recommended` sets `SecRuleEngine DetectionOnly` as a safe default, so any `SecRuleEngine On` override must be placed *after* the CRS includes in the directives string, or the WAF silently scores every rule but blocks nothing.

**SQLite concurrency** (`storage/db.go`): PRAGMAs (`busy_timeout`, `journal_mode=WAL`, `synchronous=NORMAL`) are passed via DSN query params (`_pragma=...`), not a post-open `Exec` — with `modernc.org/sqlite`, only DSN params apply to every pooled connection; a bare `Exec` only configures whichever single connection happens to run it. `SetMaxOpenConns(8)` is safe because WAL lets readers proceed concurrently with the one writer SQLite always serializes. Request logging never runs synchronously on the request path: `DB.QueueRequest` pushes onto a buffered channel (`logQueue`, cap 10000) drained by one dedicated `runLogWorker` goroutine; `DB.Close()` drains the queue before closing the connection.

**Admin UI** (`ui/handlers.go`, `ui/templates/`): one Echo group mounted at `cfg.Admin.Path` (default `/admin`) behind HTTP Basic Auth. Pages are server-rendered HTML templates with HTMX partial swaps (`renderPartial`) for live updates — e.g. the Logs page tails new rows over SSE (`/admin/logs/stream`, `/admin/api/notifications/stream`) via `ui.LogBroadcaster`, but only when no filters are active; filtered views page through SQLite directly. Frontend JS source lives in `static/js/src/*.js` and is minified by the pure-Go tool in `tools/minify` (via `go:generate`) into `static/js/dist/*.min.js`, which is `//go:embed`-ed (`assets.go`) and served at `/admin/static/js/` — there is no Node/npm toolchain in this repo. Multi-step wizards with hidden (`display:none`) steps, like the service-add form in `ui/templates/services.html`, use `novalidate` on the `<form>` plus manual JS `.value.trim()` checks instead of HTML5 `required`/`checkValidity()` — a `required` input inside a hidden step still participates in native constraint validation per spec but can't be focused for the validation bubble, so Chrome silently blocks submission with no visible error.

**Styling is Tailwind via the CDN Play script, not a build pipeline.** `ui/templates/base.html` loads `<script src="https://cdn.tailwindcss.com">` and sets a `tailwind.config` (custom `brand`/`navy`/`canvas`/`surface`/`line` colors, `sans`/`mono` font families) inline — there is no `tailwind.config.js`, no PostCSS, no purge step. All templates use `class="..."` utilities, including arbitrary-value syntax (`w-[34px]`, `bg-[#E4F5EC]`) for one-off values outside the theme scale; do not introduce `style="..."` attributes or `<style>` blocks for anything Tailwind can express. JS that toggles visibility/color (`static/js/src/*.js`) does it via `classList`, never `element.style.*` — for show/hide, keep a permanent `flex`/`block` class alongside the toggled `hidden` class (Tailwind doesn't merge a bare `hidden` removal back into a layout display value on its own).

**Metrics** (`metrics/metrics.go`): Prometheus exposition format, served at `{admin.path}/metrics` (registered inside the same Basic-Auth-protected Echo group as the rest of the admin UI — Prometheus scrape configs support `basic_auth` natively, so no separate auth path was added). `proxy/handler.go` increments `IPBlockedTotal`/`GeoBlockedTotal`/`WAFBlockedTotal` at the exact point each block decision is made, and calls `metrics.RecordRequest` once per request from inside `writeLog` (the single chokepoint every code path already funnels through for DB/SSE logging). `coraza_log_queue_depth` and `coraza_services_total` are `GaugeFunc`s that read `storage.DB.QueueDepth()`/`services.Registry.List()` live on every scrape rather than via a polling goroutine — same passive-observation pattern as service health checks.

**GeoIP database is bundled, not fetched.** `geo/GeoLite2-Country.mmdb` is `//go:embed`-ed via `geo/embedded.go` and used by `geo.New()` whenever `config.yaml`'s `geo.db_path` is empty, so the binary blocks by country out of the box with no MaxMind account or download step. Setting `geo.db_path` to a real file path overrides the bundled copy with a freshly downloaded one (MaxMind requires old GeoLite2 versions be replaced within 30 days of a new release — see `THIRD_PARTY_NOTICES.md`).

**Module layout**: `config/` (YAML load + defaults), `waf/` (Coraza engine wrapper), `services/` (DB-backed routing registry + TLS), `proxy/` (the request pipeline), `storage/` (SQLite access, schema migrations, async log queue), `blocklist/` (IP rules), `geo/` (GeoIP2 country blocking, bundled MaxMind GeoLite2), `ratelimit/` (in-process per-IP token-bucket limiter with idle-bucket eviction), `metrics/` (Prometheus instrumentation), `ui/` (admin dashboard handlers + templates), `tools/minify/` (build-time JS minifier, not shipped in the binary).

**Rate limiting** (`ratelimit/ratelimit.go`): per-IP token bucket, applied globally before geo/WAF inspection. Configured under `rate_limit:` in `config.yaml` (`enabled`, `requests_per_second` default 10, `burst` default 20). When disabled, `Allow()` is a no-op. A janitor goroutine evicts buckets idle for more than 5 minutes to bound memory under an unbounded public IP space — unlike the fixed-size `blocklist`/`geo` maps. Blocked requests return 429 and are counted by `metrics.RateLimitedTotal`.

## Distribution

No Docker — this ships as a native binary. `make dist` cross-compiles `linux/amd64`/`linux/arm64`/`windows/amd64` with `CGO_ENABLED=0` (works because every dependency, including the SQLite driver, is pure Go). `deploy/install.sh` is a one-line `curl | sudo bash` installer (Linux only): downloads + SHA256-verifies the binary, creates a dedicated non-root system user with only `CAP_NET_BIND_SERVICE` (not root) for binding privileged ports, and installs the systemd unit from `deploy/coraza-waf-mod.service` plus the prune timer units from `deploy/coraza-waf-mod-prune.{service,timer}`. Check status with `sudo systemctl status coraza-waf-mod`. `install.sh`'s `BASE_URL` is a placeholder — it needs to point wherever release binaries actually get published (the repo's remote is GitLab, not GitHub).
