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

### Phase 1 — Core Reverse Proxy + Coraza (in progress)
- [x] Echo server boots and listens
- [x] Single-backend reverse proxy working (tested: 200 proxied through)
- [ ] Coraza WAF engine initialised with **OWASP CRS loaded** ← next up
- [x] Every request runs through a Coraza transaction (`waf/engine.go`)
- [x] Interrupted requests (blocked by WAF) return 403
- [x] Real client IP extracted: `CF-Connecting-IP` → `X-Forwarded-For` → `X-Real-IP`
- [x] TLS support: Let's Encrypt auto (`mode: auto`) + custom cert (`mode: custom`) + plain HTTP (`mode: off`)

### Phase 2 — Multi-App Support (partially done)
- [x] `config.yaml` supports multiple `apps:` entries
- [x] Route by `Host` header (virtual hosting)
- [x] Route by path prefix
- [ ] Hot-reload config on SIGHUP (Phase 6)

### Phase 3 — Structured Logging to SQLite
- [ ] SQLite DB initialised (`modernc.org/sqlite`)
- [ ] `requests` log table: `timestamp, app_name, real_ip, method, path, status, blocked, reason, user_agent`
- [ ] Every proxied request logged
- [ ] Blocked requests flagged with WAF reason

### Phase 4 — IP Blocking + Geo Blocking
**IP Blocking**
- [ ] Global + per-app IP blacklist / whitelist
- [ ] In-memory map synced from SQLite (fast lookup)
- [ ] API to add / remove IPs

**Geo Blocking**
- [ ] MaxMind GeoLite2-Country `.mmdb` loaded via `geoip2-golang`
- [ ] Per-app country allow-list / block-list stored in SQLite
- [ ] Lookup on every request; block with 403 + reason

### Phase 5 — Web UI Dashboard
- [ ] Admin routes protected (basic auth or API key)
- [ ] Dashboard: stats cards (blocked today, top countries, top attacked apps) + charts
- [ ] Logs page: paginated table, filters (IP, app, date range, blocked-only)
- [ ] Blocked IPs page: add / remove / search
- [ ] Geo Rules page: manage country rules per app
- [ ] Apps page: add / edit / delete backends
- [ ] Rules page: view loaded CRS rules + custom rules
- [ ] HTMX live updates (no full-page reloads)

### Phase 6 — Polish & Production
- [ ] Rate limiting (in-process token bucket; Redis optional later)
- [ ] Config hot-reload (SIGHUP)
- [ ] `Dockerfile` + `docker-compose.yml` example
- [ ] Basic auth or API-key auth for the UI
- [ ] DB backup / restore endpoint
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] End-to-end test with simulated Cloudflare headers + real attack payloads

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
│   └── db.go              # SQLite models (logs, bans, geo rules, apps)
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

**Phase 1 — in progress.** Core proxy + WAF engine built and tested. Binary compiles and proxies requests correctly. Real IP extraction is in place.

**Next up:** Download OWASP CRS rules into `rules/` and verify WAF actually blocks attack payloads (SQL injection, XSS, etc). That completes Phase 1.

---

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-06-23 | Pure-Go SQLite (`modernc.org/sqlite`) over `mattn/go-sqlite3` | No CGO needed; single binary deployment |
| 2026-06-23 | Echo over Gin/Fiber | Good proxy middleware support + familiar API |
| 2026-06-23 | HTMX + Tailwind over React/Vue | No build step; server-rendered; simpler ops |
