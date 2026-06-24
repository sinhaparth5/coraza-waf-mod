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
make dist         # cross-compile linux/amd64 + linux/arm64 release binaries (CGO_ENABLED=0)
make checksums    # sha256sum dist/* -> dist/checksums.txt
```

Run a single test: `go test ./proxy/ -run TestName -v` (substitute the package).

**Never run `go build` directly after editing JS** — `go:generate` (which runs the JS minifier in `tools/minify`) only fires via `make build`/`make dist`, not bare `go build`. If you must, run `go generate ./...` first.

Do not start the server (`go run .`, `make run`, etc.) without the user explicitly asking each time — verify changes with throwaway `go test` files instead, and delete them once they pass.

## Architecture

**Request flow** (`proxy/handler.go`, single `Handle` method, in order): IP blocklist check → geo blocklist check → Coraza WAF inspection → reverse-proxy to the matched backend. Every stage logs to SQLite via a fire-and-forget queue, never blocking the hot path.

**Services are DB-backed, not config-driven.** `config.yaml`'s `apps:` list is only read once on first-ever startup (`storage.MigrateConfigApps`) to seed the `services` table; after that, `/admin/services` in the UI is the sole source of truth. `services.Registry` (`services/registry.go`) holds the current service list plus one pre-built `httputil.ReverseProxy` per service behind a `sync.RWMutex`, and is rebuilt wholesale via `Reload(db)` whenever a service is added/edited/removed — no restart needed. All proxies share one `backendTransport` with explicit dial (5s) and response-header (10s) timeouts, since Go's default transport has no upper bound on waiting for a backend and will otherwise stall browser connection slots.

**Routing precedence** in `Registry.Match(host, path)`: all Prefix-matched services are checked first (longest prefix wins), then Host matches — mirroring nginx's `location` blocks beating `server_name` defaults. For prefix-matched services, `proxy/handler.go`'s `Handle()` strips the matched prefix from the request path before proxying (restored before logging, so the admin UI shows the real client path) — like `proxy_pass http://backend/` in nginx. Host-matched services are passed through untouched (virtual hosting).

**Health is passive, not polled.** There is no background health-check loop; `Registry.markHealth` is driven entirely by real proxied traffic outcomes via each `ReverseProxy`'s `ErrorHandler` (failure → unhealthy) and `ModifyResponse` (response received → healthy) hooks. The one exception is `services.Probe()`, a single one-shot reachability GET run only when a service is first added through the UI, to reject obviously-dead backends before they're saved.

**TLS**: `tls.mode` in config.yaml is `off` (default) / `auto` (Let's Encrypt via `autocert`) / `custom` (static cert+key files), handled by `startAutoTLS`/`startCustomTLS` in `main.go`. Independently, each service can have its own TLS via the admin UI ("Manage" modal per row): an uploaded custom cert, or per-service auto-issue. `Registry.GetCertificateFunc` resolves certs by SNI in priority order: per-service custom cert → per-service/legacy autocert (if host is allowed by `Registry.HostPolicy()` unioned with the legacy static domain list) → global fallback. Uploaded private keys are stored on disk under `certs/services/<name>/` (mode 0600), not in `waf.db`.

**WAF engine** (`waf/engine.go`): directive order matters and has bitten this project before — `@coraza.conf-recommended` sets `SecRuleEngine DetectionOnly` as a safe default, so any `SecRuleEngine On` override must be placed *after* the CRS includes in the directives string, or the WAF silently scores every rule but blocks nothing.

**SQLite concurrency** (`storage/db.go`): PRAGMAs (`busy_timeout`, `journal_mode=WAL`, `synchronous=NORMAL`) are passed via DSN query params (`_pragma=...`), not a post-open `Exec` — with `modernc.org/sqlite`, only DSN params apply to every pooled connection; a bare `Exec` only configures whichever single connection happens to run it. `SetMaxOpenConns(8)` is safe because WAL lets readers proceed concurrently with the one writer SQLite always serializes. Request logging never runs synchronously on the request path: `DB.QueueRequest` pushes onto a buffered channel (`logQueue`, cap 10000) drained by one dedicated `runLogWorker` goroutine; `DB.Close()` drains the queue before closing the connection.

**Admin UI** (`ui/handlers.go`, `ui/templates/`): one Echo group mounted at `cfg.Admin.Path` (default `/admin`) behind HTTP Basic Auth. Pages are server-rendered HTML templates with HTMX partial swaps (`renderPartial`) for live updates — e.g. the Logs page tails new rows over SSE (`/admin/logs/stream`, `/admin/api/notifications/stream`) via `ui.LogBroadcaster`, but only when no filters are active; filtered views page through SQLite directly. Frontend JS source lives in `static/js/src/*.js` and is minified by the pure-Go tool in `tools/minify` (via `go:generate`) into `static/js/dist/*.min.js`, which is `//go:embed`-ed (`assets.go`) and served at `/admin/static/js/` — there is no Node/npm toolchain in this repo.

**Metrics** (`metrics/metrics.go`): Prometheus exposition format, served at `{admin.path}/metrics` (registered inside the same Basic-Auth-protected Echo group as the rest of the admin UI — Prometheus scrape configs support `basic_auth` natively, so no separate auth path was added). `proxy/handler.go` increments `IPBlockedTotal`/`GeoBlockedTotal`/`WAFBlockedTotal` at the exact point each block decision is made, and calls `metrics.RecordRequest` once per request from inside `writeLog` (the single chokepoint every code path already funnels through for DB/SSE logging). `coraza_log_queue_depth` and `coraza_services_total` are `GaugeFunc`s that read `storage.DB.QueueDepth()`/`services.Registry.List()` live on every scrape rather than via a polling goroutine — same passive-observation pattern as service health checks.

**Module layout**: `config/` (YAML load + defaults), `waf/` (Coraza engine wrapper), `services/` (DB-backed routing registry + TLS), `proxy/` (the request pipeline), `storage/` (SQLite access, schema migrations, async log queue), `blocklist/` (IP rules), `geo/` (GeoIP2 country blocking, MaxMind GeoLite2), `metrics/` (Prometheus instrumentation), `ui/` (admin dashboard handlers + templates), `tools/minify/` (build-time JS minifier, not shipped in the binary).

## Distribution

No Docker — this ships as a native binary. `make dist` cross-compiles `linux/amd64`/`linux/arm64` with `CGO_ENABLED=0` (works because every dependency, including the SQLite driver, is pure Go). `deploy/install.sh` is a one-line `curl | sudo bash` installer: downloads + SHA256-verifies the binary, creates a dedicated non-root system user with only `CAP_NET_BIND_SERVICE` (not root) for binding privileged ports, and installs the systemd unit from `deploy/coraza-waf-mod.service`. Check status with `sudo systemctl status coraza-waf-mod`. `install.sh`'s `BASE_URL` is a placeholder — it needs to point wherever release binaries actually get published (the repo's remote is GitLab, not GitHub).
