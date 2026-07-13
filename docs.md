# Coraza WAF Mod Documentation

> This consolidated document follows the Docusaurus sidebar order. The canonical, individually maintained pages remain in `docs/`.

---

<!-- Source: docs/overview/intro.md -->

# Coraza WAF Mod

A single-binary **Web Application Firewall + reverse proxy** for Linux, built in Go on top of
[Coraza v3](https://github.com/corazawaf/coraza) (OWASP Core Rule Set) with a built-in
HTMX/Tailwind admin dashboard. There is **no Docker requirement, no external database, and no
Node toolchain** — one binary, one SQLite file.

<div className="doc-img">
  <img
    src="/img/arch_diagram_white-bg.png"
    alt="Coraza WAF Mod Architecture: User Request → Cloudflare → OS Firewall → Coraza WAF Proxy (with SQLite waf.db and HTMX/Tailwind Admin Dashboard) → Application Service"
  />
</div>

## What it does

Coraza WAF Mod sits in front of one or more backend web applications and inspects every incoming
HTTP request before it is allowed to reach a backend. For each request it runs an ordered
pipeline of defensive checks — bot challenge, IP blocklist, rate limiting, geo blocking, and full
WAF rule inspection — and only then reverse-proxies the request to the matching backend. Every
decision (blocked or allowed) is logged asynchronously to a local SQLite database, and the whole
thing is managed live from a built-in web dashboard with no restarts required.

It is designed to be **operationally boring**: a single statically-linked binary, a single SQLite
file for all state, a systemd unit, and an optional prune timer. Everything else — services,
rules, TLS, bot settings, rate limits — is configured at runtime through the dashboard and stored
in the database.

## What's inside

- **WAF inspection** — Coraza v3 + OWASP CRS compiled in; blocks SQLi, XSS, RCE, path traversal,
  and scanners out of the box. See [WAF Inspection](/docs/security/waf).
- **Reverse proxy & multi-app routing** — host- and prefix-based routing to many backends from one
  front door, hot-reloaded with no restart. See [Architecture](/docs/overview/architecture).
- **IP & geo blocking** — manual allow/block rules, automatic IP banning, and bundled GeoLite2
  country blocking. See [IP & Geo Blocking](/docs/security/blocking).
- **Rate limiting** — per-IP token bucket, in-process or Redis-backed for multi-node. See
  [Rate Limiting](/docs/configuration/rate-limiting).
- **Bot protection** — header-based scoring with a JavaScript proof-of-work challenge, plus JA4 TLS
  fingerprinting and ASN lookup. See [Bot Protection](/docs/security/bot-and-fingerprinting).
- **Threat-intel auto-sync & webhooks** — pull external IP blocklists and forward events. See
  [Threat Intel & Webhooks](/docs/security/threat-intel-webhooks).
- **Unified threat scoring & adaptive enforcement** — a composite 0–100 per-IP risk score (autoban
  history, bot score, ASN/hosting classification, geo risk, JA4 repeat-offender history) that can, if
  enabled, automatically tighten the global rate limit or force a bot challenge for high-risk clients.
  See [Threat Score & Adaptive Enforcement](/docs/security/threat-score).
- **Varnish caching** — an optional per-service cache that sits *behind* the WAF, so nothing reaches
  the cache or backend without passing the full pipeline. See [Varnish Cache](/docs/configuration/varnish).
- **Email alerts** — daily traffic digest and instant ban-alert emails when the autoban engine blocks
  a new IP, with a display name so alerts arrive as *Coraza WAF Mod* in your inbox.
- **TLS / HTTPS** — plain HTTP, automatic Let's Encrypt, or your own certs, mixable per service. See
  [TLS Setup](/docs/configuration/tls).
- **Admin dashboard** — server-rendered HTMX + Tailwind, session-cookie auth, everything live. See
  [Using the Dashboard](/docs/configuration/dashboard).
- **REST API** — a `Bearer`-token authenticated `/api/v1` endpoint set for services, IP rules, and
  bans, separate from the session-cookie dashboard, for scripting and integrations. See
  [REST API](/docs/configuration/rest-api).
- **Prometheus metrics & request logging** — per-cause counters, async SQLite logging, an optional
  nginx-style `access.log`, and a live in-dashboard terminal view of the same stream. See
  [Metrics](/docs/configuration/metrics) and [Access Log](/docs/configuration/access-log).

Ready to install? Head to [Requirements](/docs/installation/requirements).

---

<!-- Source: docs/overview/architecture.md -->

# Architecture Deep Dive

## Request pipeline

Every request runs through a single `Handle` method, in strict order:

1. **Bot challenge gate** — non-trusted clients without a valid bypass cookie are redirected to the
   JS proof-of-work challenge (subject to global + per-service bot mode, OR'd with a force-challenge
   decision from [adaptive enforcement](/docs/security/threat-score) if enabled).
2. **IP blocklist check** — exact-match block rejects.
3. **Global rate limit** — per-IP token bucket, scaled up or down for high/low-risk IPs by the same
   adaptive-enforcement decision when enabled.
4. **Per-service rate limit** — optional, after routing (never scaled by adaptive enforcement — that
   only touches the global limiter).
5. **Geo blocklist check** — country block by resolved client IP.
6. **Coraza WAF inspection** — full CRS + custom rules, via a per-service override engine when that
   service has its own [rule exceptions](/docs/security/waf#per-service-exceptions), else the shared
   default engine.
7. **Reverse-proxy** to the matched backend.

Every stage logs the outcome via a **non-blocking queue** (buffered channel drained by one worker
goroutine), so the hot path never waits on the database. Every response — blocked or proxied — gets
its `Server` header forced to `Coraza WAF Mod` and the standard security headers applied.

## Reverse proxy & multi-app routing

Coraza WAF Mod routes to as many backend apps ("services") as you need from a single front door.
Two match modes per service:

- **Host match** — virtual hosting by `Host` header (e.g. `api.example.com` → one backend,
  `blog.example.com` → another). The request path is passed through untouched.
- **Prefix match** — route by URL path prefix (e.g. `/api` → a backend), with **automatic prefix
  stripping** before proxying, exactly like nginx `proxy_pass http://backend/`. The original client
  path is restored before logging so the dashboard shows what the client really requested.

**Routing precedence:** all prefix matches are evaluated first (**longest prefix wins**), then host
matches — mirroring nginx `location` blocks beating `server_name` defaults.

Each service gets its **own pre-built reverse proxy** with sane timeouts (5s dial, 10s response
header) so a slow/dead backend cannot stall browser connection slots indefinitely. Services are
**database-backed and hot-reloaded**: adding, editing, or removing a service rebuilds the routing
registry instantly with **no restart**.

**Passive health tracking:** there is no background polling loop. A service is marked unhealthy when
a real proxied request fails and healthy again when one succeeds. The only active check is a single
one-shot reachability probe when a service is first added (to reject obviously-dead backends before
saving).

## State & storage

Everything lives in one SQLite file via the pure-Go `modernc.org/sqlite` driver. WAL mode plus a
bounded connection pool lets readers run concurrently with the single serialized writer. Services,
rules, TLS state, sessions, rate-limit snapshots, and settings are all DB-backed. Uploaded TLS
private keys are the one exception — those live on disk at mode `0600`.

Request logging itself is **fire-and-forget**: every pipeline stage enqueues its outcome on a
buffered channel drained by a dedicated worker goroutine, so logging never blocks the request hot
path. Logs are retained for a configurable number of days and pruned by a
[separate one-shot command](/docs/configuration/log-retention).

## Hot reload

The WAF engine, bot challenger, rate-limit backend, IP blocklist, and service registry are all
swapped behind read/write mutexes, so dashboard changes apply with no restart.

## Bundled data

The GeoLite2-Country and DB-IP ASN Lite databases, the OWASP CRS, and the minified dashboard JS are
all `//go:embed`-ed into the binary — there is nothing external to fetch at runtime. Everything (the
SQLite driver, GeoIP, ASN) is pure Go, so binaries are built with `CGO_ENABLED=0` and run with no
shared-library dependencies.

## Background subsystems

Beyond the request pipeline, several long-running goroutines are started once at boot and run for the
process lifetime, each wired to a DB-backed config that can change live from the dashboard:

- the [threat-intel](/docs/security/threat-intel-webhooks) sync worker,
- the [autoban](/docs/security/blocking#automatic-ip-banning) scorer — fed every logged event, using
  the same fire-and-forget pattern as the log queue,
- the [threat score](/docs/security/threat-score) scorer — a third log fan-out hook that computes
  each IP's composite risk score asynchronously and caches it in memory for the adaptive-enforcement
  hot-path lookup,
- the [webhook](/docs/security/threat-intel-webhooks) pusher,
- the [daily-report mailer](/docs/configuration/email-alerts),
- and — when [Varnish caching](/docs/configuration/varnish) is used by any service — a permanent
  loopback-only HTTP listener that Varnish's static VCL sends cache misses to, which resolves the
  correct backend from the live service registry rather than from anything baked into Varnish's config.

## TLS fingerprinting

[JA4 and JA3](/docs/security/bot-and-fingerprinting) are computed in `GetConfigForClient` at handshake
time and cached per-connection until the connection closes, so per-request lookup never touches the
network or the database.

---

<!-- Source: docs/installation/requirements.md -->

# Requirements

| | |
|---|---|
| **OS (running)** | Linux (the installer and systemd units are Linux-only). Windows binaries can be built but the installer does not target them. |
| **Architecture** | `amd64` (x86_64) or `arm64` (aarch64). |
| **Privileges** | Root (via `sudo`) only to install the systemd service and bind ports 80/443. The service itself runs as a dedicated non-root user. |
| **Go (building only)** | Go **1.25+**. Not needed if you use a release binary. |
| **External services** | None required. Redis is optional (only for multi-node rate limiting). |

Everything — SQLite driver (`modernc.org/sqlite`), GeoIP, ASN — is pure Go, so binaries are built
with `CGO_ENABLED=0` and run with no shared-library dependencies.

---

<!-- Source: docs/installation/install.md -->

# Installation

## Option A — One-line installer

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
```

The installer is **interactive** (it prompts for admin email, password, and an optional domain).

What the installer does:

1. Detects your OS and CPU architecture (`amd64`/`arm64`).
2. Detects the **latest release** from GitLab (or honors a pinned `CORAZA_VERSION`).
3. **Downloads the matching binary and `checksums.txt`, then verifies the SHA-256 checksum** before
   installing to `/usr/local/bin/coraza-waf-mod`.
4. Prompts interactively for:
   - **Admin email** and **password** (entered twice).
   - An optional **domain name** — if given, Let's Encrypt is used; if blank, a self-signed cert is
     generated for the server's public IP.
5. Creates a dedicated non-root system user `coraza-waf-mod` (with only `CAP_NET_BIND_SERVICE`, so
   it can bind 80/443 without being root).
6. Creates `/var/lib/coraza-waf-mod/` (data + certs), seeds admin credentials into the database via
   the `setup` subcommand, and generates a self-signed cert via `gencert` when no domain is given.
7. Installs and starts three systemd units: the main service, plus a **prune service + timer**
   (log retention, runs every 15 days).

Useful environment overrides:

```bash
# Pin a specific version
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo CORAZA_VERSION=v1.0.0 bash

# Private GitLab project — supply a personal access token
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo GITLAB_TOKEN=glpat-xxxxxxxx bash

# Dry run — print every action, write nothing (no root needed)
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | DRY_RUN=1 bash
```

After it finishes:

```bash
sudo systemctl status coraza-waf-mod      # is it running?
sudo journalctl -u coraza-waf-mod -f      # follow logs
```

The dashboard is then reachable at **`https://<your-domain-or-server-ip>/admin`**. With a
self-signed certificate, your browser will show a security warning the first time — accept the
exception. You can later switch to a trusted certificate from **Settings → TLS**.

## Option B — Build from source

Requires Go 1.25+.

```bash
git clone https://gitlab.com/sinhaparth5/coraza-waf-mod.git
cd coraza-waf-mod
make build          # runs `go generate` (minifies JS) then `go build` → ./coraza-waf-mod
```

Then seed an admin account and start it:

```bash
# Create the first admin (reads the password from stdin)
printf 'your-strong-password\n' | ./coraza-waf-mod setup \
  --db ./waf.db --admin-email you@example.com

# Start the WAF + proxy on :8080
./coraza-waf-mod --db ./waf.db --listen :8080
```

:::warning[Build note]
Never run bare `go build` after editing JavaScript in `static/js/src/*.js` — the minifier runs via
`go generate`, which `make build` triggers but `go build` does not. Use `make build`, or run
`go generate ./...` first.
:::

## Option C — Pre-built release binaries

```bash
make dist          # cross-compiles linux/amd64, linux/arm64, windows/amd64 (CGO_ENABLED=0)
make checksums     # writes dist/checksums.txt
```

The binaries land in `dist/`. Copy the one for your platform, mark it executable, and run it the
same way as Option B.

---

<!-- Source: docs/installation/first-run.md -->

# First Run & Initial Setup

If you used the **installer (Option A)**, your admin account already exists (you typed it during
install) and the service is running — skip to [Using the Dashboard](/docs/configuration/dashboard).

For a **manual / source install**:

1. **Create the first admin account:**
   ```bash
   printf 'your-strong-password\n' | ./coraza-waf-mod setup \
     --db ./waf.db --admin-email you@example.com
   ```
   :::warning[Default dev credentials are insecure]
   If you start the server **without** running `setup`, a development fallback admin
   (`admin@localhost` / `admin123`) is seeded and printed in the logs. **Do not rely on this in
   production** — always run `setup` to create real credentials and change the default.
   :::
2. **Start the server:**
   ```bash
   ./coraza-waf-mod --db ./waf.db --listen :8080
   ```
3. **Open the dashboard** at `http://<host>:8080/admin` and log in.
4. **Add your first backend** under **Services** (see [Using the Dashboard](/docs/configuration/dashboard)).

---

<!-- Source: docs/installation/systemd.md -->

# Running as a systemd Service

The installer writes `/etc/systemd/system/coraza-waf-mod.service` similar to:

```ini
[Unit]
Description=Coraza WAF Mod (WAF + reverse proxy)
After=network.target

[Service]
Type=simple
User=coraza-waf-mod
Group=coraza-waf-mod
WorkingDirectory=/var/lib/coraza-waf-mod
ExecStart=/usr/local/bin/coraza-waf-mod --listen :80 --listen-tls :443 \
  --db /var/lib/coraza-waf-mod/waf.db --certs /var/lib/coraza-waf-mod/certs --retention 30
Restart=on-failure
RestartSec=5s

# Bind :80/:443 without running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Common operations:

```bash
sudo systemctl status coraza-waf-mod        # status
sudo systemctl restart coraza-waf-mod       # restart (e.g. after changing flags)
sudo journalctl -u coraza-waf-mod -f        # follow logs
sudo systemctl list-timers | grep coraza    # see the prune timer
```

To change flags (listen addresses, trusted proxies, retention), edit the `ExecStart` line, then
`sudo systemctl daemon-reload && sudo systemctl restart coraza-waf-mod`.

---

<!-- Source: docs/installation/upgrading.md -->

# Upgrading

Re-run the installer — it is upgrade-aware:

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
```

On an existing install it downloads + verifies the new binary, replaces it, and restarts the
service. **Admin credentials and certificates are never overwritten on upgrade** (the `setup` step
is idempotent for credentials). Pin a version with:

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo CORAZA_VERSION=v1.2.3 bash
```

For source installs, `git pull && make build`, then restart the service/process.

---

<!-- Source: docs/installation/building.md -->

# Building & Releasing

```bash
make build       # go generate (minify JS) + go build → ./coraza-waf-mod
make run         # build + run
make test        # go test ./...
make clean       # remove binary, minified JS, dist/
make dist        # cross-compile linux/amd64 + linux/arm64 + windows/amd64 (CGO_ENABLED=0)
make checksums   # sha256sum dist/* → dist/checksums.txt
make tag VERSION=v1.0.0   # annotated git tag + push (triggers the GitLab release pipeline)
```

Run a single package's tests:

```bash
go test ./proxy/ -run TestName -v
```

:::warning[Always use make build after editing JS]
Never run bare `go build` after editing JavaScript in `static/js/src/*.js` — the minifier runs via
`go generate`, which `make build` triggers but `go build` does not. Use `make build`, or run
`go generate ./...` first.
:::

---

<!-- Source: docs/configuration/cli.md -->

# Command-Line Interface

The binary is configured entirely through **CLI flags** (bootstrap settings) plus the **admin
dashboard / database** (everything runtime). There is no longer a `config.yaml` that the running
server reads — all knobs are flags or DB-managed.

## Runtime flags

Start the WAF/proxy/dashboard by running the binary with any of these flags:

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:8080` | HTTP listen address. |
| `--listen-tls` | *(empty)* | HTTPS listen address. Empty = HTTP only. |
| `--trusted-proxies` | *(empty)* | Comma-separated CIDRs allowed to supply `X-Forwarded-For` / `X-Real-IP`. |
| `--db` | `waf.db` | SQLite database path. |
| `--certs` | `./certs` | TLS certificate cache directory (Let's Encrypt files). |
| `--waf-rules` | *(empty)* | Directory of extra `.conf` WAF rules, loaded on top of OWASP CRS. |
| `--geo-db` | *(empty)* | Path to an external `GeoLite2-Country.mmdb`. Empty = use bundled DB. |
| `--retention` | `30` | Request-log retention in days. `0` = keep forever (used by `prune`). |
| `--tls-cert` | *(empty)* | PEM certificate file for the HTTPS fallback (self-signed). |
| `--tls-key` | *(empty)* | Matching PEM private key for `--tls-cert`. |
| `--access-log` | *(empty)* | nginx-combined-format access log file path. Empty = disabled. See [Access Log](/docs/configuration/access-log). |
| `--access-log-max-size-mb` | `100` | Rotate the access log after it reaches this many MB. |
| `--access-log-max-backups` | `5` | Number of rotated access log files (`access.log.1`, `.2`, …) to keep. |

Example (HTTP + HTTPS, behind a known load balancer):

```bash
./coraza-waf-mod \
  --listen :80 \
  --listen-tls :443 \
  --tls-cert /var/lib/coraza-waf-mod/certs/self-signed.crt \
  --tls-key  /var/lib/coraza-waf-mod/certs/self-signed.key \
  --trusted-proxies 10.0.0.0/8,192.168.0.0/16 \
  --db /var/lib/coraza-waf-mod/waf.db \
  --certs /var/lib/coraza-waf-mod/certs \
  --retention 30
```

## Subcommands

Each subcommand does one thing and exits (it does **not** start the server).

### `setup` — seed admin credentials and optional ACME config

```bash
coraza-waf-mod setup --db waf.db --admin-email you@example.com \
  [--domain example.com] [--acme-email contact@example.com]
# Password is read from stdin (one line).
```

- **Idempotent for credentials:** if an admin already exists, the credential step is skipped — safe
  to re-run on upgrade without overwriting a changed password.
- If `--domain` is given, the domain and ACME contact email are stored so Let's Encrypt can issue a
  certificate. `--acme-email` defaults to the admin email if omitted.

### `gencert` — generate a self-signed certificate

```bash
coraza-waf-mod gencert --cert cert.pem --key key.pem \
  --hosts 203.0.113.10,waf.internal [--days 3650]
```

- Produces a self-signed **ECDSA P-256** certificate with the given hostnames/IPs as SANs (so
  browsers don't complain about a hostname mismatch on IP-based access). Pure Go — no openssl.

### `prune` — delete old request logs

```bash
coraza-waf-mod prune --db waf.db --retention 30
```

- Opens the DB, deletes request rows older than the retention window **in batches** (with short
  pauses between batches so SQLite's single write lock isn't held for the whole delete), and exits.
- `--retention 0` or negative disables pruning. Intended to be run by cron or the bundled systemd
  timer, never inside the live server process. See [Log Retention & Pruning](/docs/configuration/log-retention).

### `version`

```bash
coraza-waf-mod version        # or: coraza-waf-mod --version
```

---

<!-- Source: docs/configuration/dashboard.md -->

# Using the Dashboard

The dashboard lives at `/admin` and is behind session-cookie login. Every change below applies
**live** — no restarts. Each page is HTMX-driven, so adding/removing a row swaps just that part of
the page. This section walks through **every feature and exactly how to use it**, including the
underlying HTTP routes (handy if you want to script against them).

:::info[How "implement" works here]
You don't edit files or restart anything to use a feature. Each dashboard form maps to a route that
writes the change to `waf.db` and then **hot-reloads** the relevant subsystem (registry, blocklist,
geo, WAF engine, rate limiter). The steps below are the implementation.
:::

<div className="doc-img">
  <img
    src="/img/docs/docs_dashboard.png"
    alt="Coraza WAF Mod dashboard home — live traffic chart, requests today, blocked today, bot shield summary, and top threats panel"
  />
</div>

## Services (backend apps) — *what gets proxied*

**Page:** `/admin/services` · **Purpose:** define which backend each incoming request is routed to.

**Add a service:**

1. Go to **Services → Add**. The add form is a short wizard.
2. Fill in:
   - **Name** — a label for the service (e.g. `api`).
   - **Match type** — `host` (virtual hosting by `Host` header) or `prefix` (route by URL path
     prefix).
   - **Match value** — the host (`api.example.com`) or the prefix (`/api`).
   - **Backend** — the upstream URL, e.g. `http://127.0.0.1:8080`.
   - **(Optional) Rate limit** — requests/second (`rps`) and `burst` for this service alone. Leave
     `0` to inherit the global limiter only.
3. Click **Add**. Before saving, the server **validates** the backend URL and runs a **one-shot
   reachability probe** — if the backend is unreachable, the save is rejected with an inline error
   ("fix the backend or try again before adding"). This prevents adding dead upstreams.
4. On success the routing registry is rebuilt instantly and the new row appears.

<div className="doc-img">
  <img
    src="/img/docs/docs_service.png"
    alt="Services page showing the Add Service wizard on the left and the configured services list on the right with host match, TLS, rate limit, and bot mode controls per row"
  />
</div>

**Behavior to know:**

- **Prefix routing strips the prefix** before proxying (so `/api/users` → backend `/users`), like
  nginx `proxy_pass http://backend/`. The original path is restored for logging.
- **Longest prefix wins**, and all prefix matches are checked before host matches.
- **Per-service TLS requires a host-matched service.** Prefix services can't have their own
  certificate (there's no SNI host to key it on) — the TLS panel will say so.

**Edit / manage a service:** use the **Manage** controls on a row to set per-service TLS (below),
per-service **bot mode** (`POST /admin/services/bot/:id` with `bot_mode` = `inherit`/`always`/`off`),
per-service **rate limit** (`POST /admin/services/ratelimit` with `service_id`, `rps`, `burst`), and
the **Cache** toggle, which routes this service through Varnish when the global Varnish switch is on
(see [Varnish Cache Integration](/docs/configuration/varnish)).

**Delete a service:** the trash control issues `DELETE /admin/services/:id` and rebuilds the
registry.

**Routes:** `GET /services`, `POST /services` (add), `DELETE /services/:id`,
`POST /services/ratelimit`, `POST /services/bot/:id`, plus the TLS routes below.

## Blocks — IP rules & geo/country rules

There are two independent block lists, both enforced **early** in the pipeline and both hot-reloaded
on change. See [IP & Geo Blocking](/docs/security/blocking) for how they fit the pipeline.

### IP rules

**Page:** `/admin/ip-rules` · **Purpose:** manually allow or block a single IP or CIDR range.

1. Go to **IP Rules**.
2. Enter:
   - **IP / CIDR** — accepts a single IPv4/IPv6 address (`1.2.3.4`, `::1`) **or** a CIDR
     (`10.0.0.0/8`). Anything else is rejected with a format hint.
   - **Rule type** — `block` or `allow`.
   - **(Optional) App/scope** — leave empty for a global rule, or scope it to a named app.
3. Submit. The rule is written and the in-memory IP blocklist reloads immediately, so the next
   request from that IP is affected.
4. **Remove** a rule with the row's delete control (`DELETE /admin/ip-rules/:id`).

<div className="doc-img">
  <img
    src="/img/docs/docs_ip_rules.png"
    alt="IP Rules page — Add IP Rule form on the left with IP/CIDR input, scope selector, and block/allow toggle; Active IP Rules list on the right with rules overview stats"
  />
</div>

These manual rules are evaluated alongside the IPs pulled in automatically by
[threat-intel sync](/docs/security/threat-intel-webhooks) and the autoban engine (see below).

**Pagination.** The list is paginated (`GET /admin/ip-rules/rows` serves the Prev/Next buttons via
HTMX without a full page reload) rather than loading the whole table — a busy autoban setup can grow
this into the thousands of rows. The "Rules overview" block/allow percentages are computed from a
separate query against the whole table, not just the current page.

**Threat score badges.** Each row shows a **"Score N"** badge — the same composite 0–100
[threat score](/docs/security/threat-score) shown in the log detail view, bulk-fetched for the
current page in one query.

**Routes:** `GET /ip-rules`, `POST /ip-rules` (`app_name`, `ip`, `rule_type`), `DELETE /ip-rules/:id`.

#### Automatic banning

The **Automatic banning** card on the same IP Rules page configures the autoban engine — the system
that watches blocked events and permanently bans IPs that cross a score threshold.

1. Toggle **Enable automatic banning** to activate it.
2. Set **Score threshold** (default 10) and **Window (minutes)** (default 10).
3. Click **Save**. Changes apply immediately via hot reload.

Auto-banned IPs appear in the Active IP Rules list with an amber **Auto** badge and a machine-stamped
ban reason note. Admin-added **allow** rules always win — the autoban engine never overwrites them.

See [Automatic IP Banning](/docs/security/blocking#automatic-ip-banning) for scoring details and
threshold guidance.

**Routes:** `POST /admin/ip-rules/autoban` (`autoban_enabled`, `autoban_threshold`, `autoban_window`).

#### Adaptive enforcement

Next to Automatic banning, the **Adaptive enforcement** card configures threat-score-driven scaling of
the global rate limit and forced bot challenges — see
[Threat Score & Adaptive Enforcement](/docs/security/threat-score) for the full mechanism.

:::warning[Disabled by default]
Unlike autoban, this is **off out of the box**. It rides on a heuristic composite score (the ASN/hosting
classification can misfire) and includes a security-*loosening* action (relaxing limits for low-risk
IPs) — look at real scores on this page for a while before turning it on.
:::

1. Toggle **Enable adaptive enforcement**.
2. Set **High-risk threshold** (default 70) and **rate scale** (default `0.3`, i.e. cut the limit to
   30%) — applied when a client's score is at or above this.
3. Set **Low-risk threshold** (default 10) and **rate scale** (default `1.5`) — applied when a
   client's score is at or below this.
4. Set a separate, stricter **Force-challenge threshold** (default 70) — only past this does a
   high-risk client also get force-challenged; tightening the rate limit and forcing a challenge don't
   have to happen at the same score.
5. Click **Save**. Applies live via hot reload — no restart.

**Routes:** `POST /admin/ip-rules/adaptive` (`adaptive_enabled`, `adaptive_high_threshold`,
`adaptive_low_threshold`, `adaptive_high_rate_scale`, `adaptive_low_rate_scale`,
`adaptive_force_challenge_threshold`).

### Geo / country rules

**Page:** `/admin/geo-rules` · **Purpose:** block or allow whole countries.

1. Go to **Geo Rules**.
2. Enter a **2-letter ISO country code** (e.g. `RU`, `CN`, `US` — case-insensitive) and a rule type
   (`block`/`allow`), optionally scoped to an app.
3. Submit. The geo blocker reloads instantly. Country is determined from the
   [resolved real client IP](/docs/security/trusted-proxy) using the bundled GeoLite2 database, so it
   works correctly behind Cloudflare / a trusted proxy.
4. **Remove** with the row's delete control (`DELETE /admin/geo-rules/:id`).

<div className="doc-img">
  <img
    src="/img/docs/docs_geo_block.png"
    alt="Geo Rules page — Add Geo Rule form with country code input and block/allow selector; Active Geo Rules list showing a CN block rule with global scope and rules overview stats"
  />
</div>

**Routes:** `GET /geo-rules`, `POST /geo-rules` (`app_name`, `country_code`, `rule_type`),
`DELETE /geo-rules/:id`.

:::note[WAF rule blocks (related)]
The **WAF Rules** page (`/admin/waf-rules`) lists CRS rules and lets you **disable** a noisy rule by
ID with a reason and a **Scope** — `Global (all services)` or one specific service
(`POST /admin/waf-rules/disable` with `rule_id`, `reason`, `service`) — and re-enable a rule
(`DELETE /admin/waf-rules/:id` for a global exception, `DELETE /admin/waf-rules/service/:id` for a
per-service one). The WAF engine rebuilds itself from the current disabled-rule list(s), so the
change is live. See [WAF Inspection](/docs/security/waf#per-service-exceptions).
:::

## Certificates & per-service TLS

There are two related surfaces: a reusable **certificate pool**, and **per-service TLS** assignment.
For the full TLS picture see [TLS Setup](/docs/configuration/tls).

### Certificate pool

**Page:** `/admin/certificates` · **Purpose:** store named cert/key pairs you can reuse across
services.

1. Go to **Certificates → Add**.
2. Enter:
   - **Name** — a label (e.g. `wildcard-example-com`).
   - **Certificate (PEM)** — paste the full certificate chain.
   - **Private key (PEM)** — paste the matching key.
3. Submit. The certificate is parsed/validated; the **private key is written to disk at mode
   `0600`** (never stored in the database), and the cert appears in the pool with its expiry.
4. **Delete** a cert with its delete control (`DELETE /admin/certificates/:id`).

**Routes:** `GET /certificates`, `POST /certificates` (`name`, `cert_pem`, `key_pem`),
`DELETE /certificates/:id`.

### Assigning TLS to a service

Open a **host-matched** service's **Manage → TLS** panel. You have these options (all require a
host-matched service — prefix services are rejected):

- **Upload a custom cert** — paste `cert_pem` + `key_pem` for this service only
  (`POST /admin/services/tls/upload`). Stored on disk under `certs/services/<name>/`.
- **Assign a pool certificate** — pick one of your saved certificates
  (`POST /admin/services/tls/pool` with `cert_id`).
- **Enable auto-issue (ACME)** — Let's Encrypt provisions a cert for the service's host on first
  request (`POST /admin/services/tls/auto`). **Requires an ACME email to be set first** (see
  Settings, below); without it the action does nothing.
- **Clear TLS** — remove per-service TLS and fall back to the global cert
  (`POST /admin/services/tls/clear`).

At handshake time certificates resolve by SNI: **per-service custom → per-service/pool/legacy
autocert → global fallback.**

## Request logs

**Page:** `/admin/logs` · **Purpose:** see, filter, export, and live-tail every request decision.

**Live tail.** With **no filters set, on page 1**, new rows stream in over Server-Sent Events
(`/admin/logs/stream`) — you watch traffic in real time. Applying any filter switches to paged
history queried directly from SQLite (so you can page deep without the stream interfering). You can
force history mode with `?mode=history`.

<div className="doc-img">
  <img
    src="/img/docs/docs_logs.png"
    alt="Live Logs page showing the live stream active indicator, date/app/status filters, and the request log table with time, app, IP, method, path, status, and duration columns"
  />
</div>

**Filtering.** Use the filter controls; they map to query parameters on `GET /admin/logs`:

| Filter | Param | Example |
|---|---|---|
| App / service | `app` | `api` |
| Status class | `status` | `2xx`, `4xx`, `5xx` |
| From (datetime) | `from` | `2026-06-01T09:00` |
| To (datetime) | `to` | `2026-06-29T17:30` |
| Page | `page` | `2` |

(`from`/`to` use the HTML `datetime-local` format `YYYY-MM-DDTHH:MM`.)

**Detail view.** Click a row to open `GET /admin/logs/:id` — full request headers, the matched WAF
rule (if any), the block reason/stage, status, and the resolved country/ASN.

<div className="doc-img">
  <img
    src="/img/docs/docs_logs_detail.png"
    alt="Log detail view showing timestamp, app/service, host, real client IP vs proxy/CDN IP, country, query string, user agent, request ID, ASN, ISP/organisation, and TLS connection details"
  />
</div>

**Export.** The **Export** button hits `GET /admin/logs/export` with the *same* filter query params
and downloads a CSV of the matching rows — so you can export exactly what you've filtered to.

**Retention.** Logs are pruned by the separate `prune` command / systemd timer, not from this page
(see [Log Retention & Pruning](/docs/configuration/log-retention)).

**Routes:** `GET /logs`, `GET /logs/stream` (SSE), `GET /logs/:id`, `GET /logs/export`.

## Settings

**Page:** `/admin/settings` · **Purpose:** admin account, security subsystems, and integrations.

<div className="doc-img">
  <img
    src="/img/docs/docs_settings.png"
    alt="Settings page showing the Account section with current email, new email, new password, and confirm password fields, plus the Database backup download button"
  />
</div>

**Change admin credentials.** Enter your **current password**, then a **new email** and/or **new
password** (typed twice). Submitting (`POST /admin/settings/credentials` with `current_password`,
`new_email`, `new_password`, `confirm_password`) re-hashes the password with bcrypt and invalidates
old sessions. Do this immediately if you started from the dev fallback (`admin@localhost` /
`admin123`).

**Bot protection.** Toggle the global challenger and tune it (`POST /admin/settings/bot` with
`bot_enabled=1`, `bot_threshold`, `bot_ttl`):

- **Enabled** — turn the JS proof-of-work challenge on/off globally.
- **Threshold** — the anomaly score above which a client is challenged.
- **TTL** — how long a solved bypass cookie stays valid (seconds).

Per-service overrides (`inherit`/`always`/`off`) are set from each service's Manage panel. See
[Bot Protection](/docs/security/bot-and-fingerprinting).

**Rate limiting backend.** Choose the backend and (for Redis) its connection
(`POST /admin/settings/ratelimit` with `rl_backend` = `memory`/`redis`, `rl_redis_addr`,
`rl_redis_password`). Use **Test connection** (`POST /admin/settings/ratelimit/test`) to verify
Redis reachability **before** saving. Switching backends is a hot reload. See
[Rate Limiting](/docs/configuration/rate-limiting).

**ACME email.** Set the Let's Encrypt contact email (`POST /admin/settings/acme-email` with
`email`). This must be set before per-service auto-issue or global ACME will work.

**Webhooks.** Configure event delivery (`POST /admin/settings/webhook` with `webhook_url`,
`webhook_secret`, `webhook_enabled=1`, and one or more `webhook_events` checkboxes). If no events
are selected it defaults to `blocked`. Delivery is asynchronous and signed with the secret; a slow
endpoint never blocks logging. See [Threat Intel & Webhooks](/docs/security/threat-intel-webhooks).

**Threat-intel sources.** On **Threat Intel** (`/admin/threat-intel`): add a source with a **label**,
a **URL** to a plain-text IP/CIDR list, and a sync **interval (hours)** (`POST /admin/threat-intel`).
Each row can be **toggled** on/off (`POST /admin/threat-intel/:id/toggle`), **synced now**
(`POST /admin/threat-intel/:id/sync`), or **deleted** (`DELETE /admin/threat-intel/:id`). Synced IPs
flow into the IP blocklist automatically.

**Varnish Cache.** Global on/off switch for the [Varnish integration](/docs/configuration/varnish)
(`POST /admin/settings/varnish` with `varnish_enabled`, `varnish_addr`). While off, every service
proxies straight to its backend even if individually marked cacheable. `varnish_addr` **must be a
loopback address** — anything else is rejected outright, since that port would bypass the WAF pipeline.

**Email alerts.** Configure the [daily report / ban alert](/docs/configuration/email-alerts) emails
(`POST /admin/settings/email` with `email_enabled`, `email_to`, `email_token`). Delivery is via
**Cloudflare Email Service** — **only the recipient list and the Cloudflare API token are
configurable**; the SMTP host, port, username, and sender are fixed in code. The token field is never
pre-filled once saved, so leave it blank on subsequent saves to keep the existing value. **Send test
report** (`POST /admin/settings/email/test`) sends an on-demand report from the currently saved config,
so you can verify credentials before enabling the schedule.

**Database backup.** `GET /admin/settings/backup` downloads a copy of the entire `waf.db`. Treat the
download as sensitive — it contains the bcrypt admin hash and challenge secret. Store it securely.

**API Keys.** The **API Keys** card creates and revokes bearer tokens for the [REST
API](/docs/configuration/rest-api). Enter a **name** (e.g. `ci-deploy`) and click **Create key**
(`POST /admin/settings/api-keys` with `name`) — the **full key is shown exactly once**; copy it
immediately, since only its hash and a short display prefix are stored afterward. **Revoke** a key
with its row's delete control (`DELETE /admin/settings/api-keys/:id`) — any request already using
that token is rejected on its very next call.

**Reload custom WAF rules.** If you use `--waf-rules` to layer custom `.conf` files on top of the
OWASP CRS, editing those files on disk is **not** picked up automatically — send `SIGHUP` to the
running process (`kill -HUP $(pidof coraza-waf-mod)`) to rebuild the WAF engine in place. This is the
*only* thing that needs SIGHUP; services, bot settings, rate limits, and everything else in this
section already hot-reload on save.

## Dashboard home, notifications & metrics

- **Home** (`/admin`) shows live traffic and threat charts (`/admin/api/traffic`,
  `/admin/api/threats`) and an at-a-glance summary.
- **Notifications** stream in over SSE (`/admin/api/notifications/stream`); mark them seen with the
  bell control.
- **Metrics** at `/admin/metrics` serve Prometheus exposition format, behind the **same
  session-cookie admin auth** as the rest of the dashboard — **not** HTTP Basic Auth. A scrape without
  a valid session cookie is redirected (302) to the login page rather than challenged for
  credentials, so a stock Prometheus `basic_auth:` scrape config will not work out of the box. See
  [Metrics](/docs/configuration/metrics).

---

<!-- Source: docs/configuration/rest-api.md -->

# REST API

Alongside the session-cookie dashboard, Coraza WAF Mod exposes a `Bearer`-token authenticated REST
API at **`{admin path}/api/v1/*`** (default `/admin/api/v1`) — a separate Echo route group, sibling
to the dashboard group rather than nested inside it.

:::info[Why bearer tokens instead of the session cookie]
A bearer token carried in an `Authorization` header, unlike a cookie, isn't automatically attached by
the browser to cross-site requests — so this group intentionally skips the dashboard's
session-cookie auth *and* CSRF middleware, both of which exist specifically to stop cookie-based
cross-site request forgery, not to gate a header-based token.
:::

## Creating a key

1. Go to **Settings → API Keys**, enter a name, and click **Create key**
   (see [API Keys](/docs/configuration/dashboard#settings)).
2. The **full key is shown exactly once** (`cwaf_` + 40 hex characters) — copy it immediately. Only a
   SHA-256 hash and a short display prefix are persisted, so it cannot be shown again — only revoked
   and replaced with a new one.
3. Send it on every request: `Authorization: Bearer cwaf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`.

Keys are **all-or-nothing** in v1 — full read-write, no read-only scope.

## Brute-force protection

Failed auth attempts (missing/malformed header, unknown key) are throttled **per client IP** with the
same policy as the dashboard login: 5 failures in 15 minutes triggers a 15-minute lockout, returned as
`429` with a `Retry-After`-style message. See
[Trusted-Proxy / Real Client IP](/docs/security/trusted-proxy) for how the client IP is resolved
behind a proxy.

## Endpoints

All request/response bodies are JSON. Every endpoint reuses the exact same `storage.DB` /
`services.Registry` / `blocklist.IPBlocklist` calls the dashboard's own HTMX handlers call, so
validation and hot-reload behavior are identical to using the UI.

### Services

| Method | Path | Notes |
|---|---|---|
| `GET` | `/services` | List all services. |
| `POST` | `/services` | Create. Body: `name`, `match_type` (`host`\|`prefix`), `match_value`, `backend`, optional `rate_limit_rps`, `rate_limit_burst`. Runs the same reachability probe as the dashboard's add wizard — an unreachable backend is rejected. |
| `GET` | `/services/:id` | Fetch one. |
| `PUT` | `/services/:id` | Partial update. Body fields are all optional pointers — an omitted field is left unchanged, unlike an empty string, which clears it. Accepts `name`, `host`, `prefix`, `backend`, `rate_limit_rps`, `rate_limit_burst`, `bot_mode` (`inherit`\|`always`\|`off`). |
| `DELETE` | `/services/:id` | Remove. |

### IP rules

| Method | Path | Notes |
|---|---|---|
| `GET` | `/ip-rules` | List all IP/CIDR rules (manual, threat-intel-synced, and auto-banned). |
| `POST` | `/ip-rules` | Create. Body: `app_name` (empty = global), `ip` (address or CIDR), `rule_type` (`block`\|`allow`). |
| `DELETE` | `/ip-rules/:id` | Remove. |

### Bans

There is **no separate ban table** — a "ban" is just a global (`app_name == ""`) `block` row in
`ip_rules`, the same row shape the [autoban](/docs/security/blocking#automatic-ip-banning) engine
writes.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/bans` | `ip-rules` filtered to global block rows only. |
| `POST` | `/bans` | Body: `ip`, optional `reason`. Written with a `"Banned via API — "` note prefix — distinct from autoban's own `"Auto-banned — "` prefix, so the two sources stay distinguishable on the IP Rules page's amber "Auto" badge. |
| `DELETE` | `/bans/:id` | Unban — identical to `DELETE /ip-rules/:id` on the same row. |

## Response shapes

`GET`/`POST` responses for services and IP rules return the underlying storage struct as-is. Neither
struct carries JSON tags, so the field names are the **exact, capitalized** Go field names — not
`snake_case` (contrast with request bodies, e.g. `apiCreateServiceRequest`, which do use explicit
`snake_case` json tags, as documented per-endpoint above).

```json title="GET /api/v1/services/3"
{
  "ID": 3,
  "Name": "api",
  "Host": "",
  "Prefix": "/api",
  "Backend": "http://127.0.0.1:9000",
  "CreatedAt": "2026-06-01T09:00:00Z",
  "TLSMode": "",
  "RateLimitRPS": 0,
  "RateLimitBurst": 0,
  "BotMode": "inherit",
  "CacheEnabled": false,
  "CacheTTLFloor": 0,
  "CacheTTLCeiling": 0,
  "CacheGrace": 0,
  "CacheKeep": 0
}
```

(Trimmed for brevity — the full struct also carries `TLSCertPath`, `TLSKeyPath`, `TLSExpiresAt`,
`CertID`, `CacheBySession`, and `SessionCookieName`.)

```json title="GET /api/v1/ip-rules"
[
  {
    "ID": 118,
    "AppName": "",
    "IP": "203.0.113.10",
    "RuleType": "block",
    "Note": "Auto-banned — score 12 in 10m window",
    "CreatedAt": "2026-07-11T12:51:40Z"
  }
]
```

Errors are a flat JSON object: `{"error": "name, backend, match_type (host|prefix), and match_value are required"}`,
with the HTTP status carrying the category (`400` validation, `401`/`429` auth, `404` not found,
`500` server error).

## Example

```bash
# Create a service — the add wizard's reachability probe runs here too, so
# an unreachable backend is rejected with a 400 before anything is saved.
curl -X POST https://your-host/admin/api/v1/services \
  -H "Authorization: Bearer cwaf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"name":"api","match_type":"prefix","match_value":"/api","backend":"http://127.0.0.1:9000"}'

# Partial update — only bot_mode changes; name/host/prefix/backend/rate limit
# are left exactly as they were, since PUT fields are optional pointers.
curl -X PUT https://your-host/admin/api/v1/services/3 \
  -H "Authorization: Bearer cwaf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"bot_mode":"always"}'

# Ban an IP
curl -X POST https://your-host/admin/api/v1/bans \
  -H "Authorization: Bearer cwaf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.10","reason":"credential stuffing"}'
```

---

<!-- Source: docs/configuration/tls.md -->

# TLS Setup In Depth

There are three modes, mixable per service:

- **Plain HTTP** (default) — no TLS.
- **Automatic Let's Encrypt (ACME)** — provide a domain + contact email; certificates are issued on
  first HTTPS request and cached on disk.
- **Your own certificate** — supply a PEM cert/key as the global fallback, and/or upload a custom
  cert **per service** from the dashboard.

**Per-service TLS:** each backend can have its own uploaded cert or its own auto-issued cert.
Certificates are resolved by SNI: per-service custom cert → per-service/legacy autocert → global
fallback. Uploaded private keys are stored **on disk** under `certs/services/<name>/` with `0600`
permissions — never in the database.

## 1. Self-signed (IP-based deployments)

Generate a cert and point the binary at it:

```bash
coraza-waf-mod gencert --cert /var/lib/coraza-waf-mod/certs/self-signed.crt \
  --key /var/lib/coraza-waf-mod/certs/self-signed.key --hosts 203.0.113.10
# then run with:
--listen :80 --listen-tls :443 \
--tls-cert /var/lib/coraza-waf-mod/certs/self-signed.crt \
--tls-key  /var/lib/coraza-waf-mod/certs/self-signed.key
```

The `gencert` subcommand produces a self-signed **ECDSA P-256** certificate with hostname/IP SANs,
so IP-based deployments get HTTPS without openssl. Browsers will warn on a self-signed cert; add an
exception, or move to ACME once you have a domain.

## 2. Automatic Let's Encrypt (ACME)

Store a domain + contact email (the installer does this when you enter a domain; manually it's
`setup --domain … --acme-email …`), then run with `--listen :80` (for the ACME HTTP-01 challenge +
redirect) and `--listen-tls :443`. The certificate is provisioned on the first HTTPS request and
cached under `--certs`. **DNS for the domain must point at the server before the first request.**

## 3. Per-service certificates

From a service's **Manage** panel, upload a custom cert/key or enable per-service auto-issue.
Certificates are resolved by SNI at handshake time: **per-service custom → per-service/legacy
autocert → global fallback.** Uploaded private keys are stored on disk (`certs/services/<name>/`,
mode `0600`), never in the database.

See [Certificates & per-service TLS](/docs/configuration/dashboard) in the dashboard walkthrough for
the exact forms and routes.

---

<!-- Source: docs/configuration/rate-limiting.md -->

# Rate Limiting In Depth

Coraza WAF Mod applies **per-client-IP token-bucket** limiting globally ahead of geo/WAF inspection,
plus optional **per-service** limits. There are two interchangeable backends, chosen from the
dashboard (**Settings → Rate limiting**); switching is a hot reload with no restart.

## How the token bucket works

Each tracked IP gets a bucket holding up to `burst` tokens, refilled continuously at `rps` tokens per
second. A request consumes one token; if the bucket is empty, the request is rejected
(`RateLimitedTotal` / `rate_limited` in the log). `burst` is effectively "how many requests can arrive
back-to-back before throttling kicks in," and `rps` is the sustained long-run rate after that burst is
spent.

*Example:* `rps=5, burst=20` allows a client to fire 20 requests instantly, then sustain roughly 5
requests/second indefinitely — a sudden 100-request burst gets the first 20 through and throttles the
rest until tokens refill.

The **global limiter is disabled by default** (no rate limiting at all until you opt in from
Settings).

## In-process limiter (default backend)

A per-IP token bucket lives in memory; its state is snapshotted to SQLite **every 10 seconds** and
restored on startup, so limits survive restarts. Idle buckets (no traffic for 5 minutes) are reclaimed
by a background janitor so the bucket map stays bounded despite an unbounded number of distinct
client IPs over time. This is the right choice for a single node.

## Redis backend (multi-node)

Select Redis in the dashboard and provide the address + password. The limiter becomes an atomic
Redis Lua-script token bucket shared across all WAF instances, so a cluster enforces one combined
limit. If Redis becomes unreachable, the backend **fails open** (it allows traffic rather than
blocking everything).

Use **Test connection** in Settings to verify Redis reachability **before** saving.

## Configuration reference

| Setting | Form field | Meta key | Notes |
|---|---|---|---|
| Enabled | `rl_enabled` | `ratelimit_enabled` | Off by default. |
| Requests/sec | `rl_rps` | `ratelimit_rps` | Sustained rate once burst is spent. |
| Burst | `rl_burst` | `ratelimit_burst` | Max tokens a bucket can hold; effectively the allowed instantaneous spike. |
| Backend | `rl_backend` | *(derived, see below)* | `memory` or `redis`. |
| Redis address | `rl_redis_addr` | `redis_addr` | `host:port`. |
| Redis password | `rl_redis_password` | `redis_password` | Empty if Redis has no auth. |

Saved via `POST /admin/settings/ratelimit`; test Redis reachability first with
`POST /admin/settings/ratelimit/test` (same `rl_redis_addr`/`rl_redis_password` fields, doesn't
persist anything).

:::note[There's no standalone "backend" flag in storage]
Startup and every reload derive the backend from whether a Redis address is currently stored, not
from a separate persisted choice: `rl_backend=redis` **pings Redis synchronously** during the save
(rejecting the save outright if it's unreachable) and then stores the address; `rl_backend=memory`
clears the stored Redis address. So "the backend" is really just "is `redis_addr` set or empty" at
read time.
:::

## Per-service limits

Each service can carry its own limiter (always in-process — per-service distribution isn't needed).
Set it from the service's Manage panel (`rps` + `burst`), or in the add wizard. These run **after**
the global limit, so a request must clear both. Per-service limits are never affected by
[adaptive enforcement](/docs/security/threat-score#adaptive-enforcement) — that only scales the
global limiter.

## Ordering

Global rate limiting runs **early** in the pipeline (after the IP blocklist, before geo and WAF), so
throttled clients are rejected cheaply. See [Architecture](/docs/overview/architecture) for the full
pipeline order.

---

<!-- Source: docs/configuration/log-retention.md -->

# Log Retention & Pruning

Request logs accumulate in SQLite. Pruning is **not** automatic inside the running server; it is a
separate one-shot command so a multi-second delete never shares the live process's DB connection
pool with request traffic.

Run it from cron or the bundled systemd timer:

```bash
coraza-waf-mod prune --db /var/lib/coraza-waf-mod/waf.db --retention 30
```

The installer sets up `coraza-waf-mod-prune.service` + `.timer` to run every 15 days automatically.
Deletes happen in batches (2000 rows) with short pauses, so SQLite's single write lock isn't held
for the entire operation.

The retention window is also expressible at runtime via the `--retention` flag (days; `0` = keep
forever). See the [CLI reference](/docs/configuration/cli) for the `prune` subcommand.

---

<!-- Source: docs/configuration/access-log.md -->

# Access Log

Coraza WAF Mod can write an **nginx-combined-format** access log to a plain text file — independent
of the SQLite-backed request log the dashboard reads from — for tooling that expects one: `fail2ban`,
log shippers, `grep`/`awk`, `logrotate`-style pipelines.

## Enabling it

It's **opt-in**, off by default:

```bash
./coraza-waf-mod --access-log /var/log/coraza-waf-mod/access.log
```

| Flag | Default | Description |
|---|---|---|
| `--access-log` | *(empty)* | File path. Empty disables the writer entirely. |
| `--access-log-max-size-mb` | `100` | Rotate after the file reaches this size. |
| `--access-log-max-backups` | `5` | How many rotated files (`access.log.1`, `.2`, …) to keep before the oldest is pruned. |

Rotation is handled in-house, matching this project's "handle your own maintenance" approach
elsewhere (e.g. `coraza-waf-mod prune` + a systemd timer instead of an external log-rotation tool for
the SQLite side) — no external dependency is required.

## Format notes

Each line follows the standard nginx combined log format. Two fields don't apply to this project and
render as the conventional `-` placeholder rather than a fabricated value: response byte count and
the `Referer` header aren't tracked on the underlying request-log row (the same placeholder every
combined-format line already uses for the identd/userid fields).

## Live terminal view in the dashboard

The **Logs** page (`/admin/logs`) has a **Table / Terminal** toggle. Terminal mode shows a
dark, monospace panel of raw access-log lines streamed live over SSE
(`GET /admin/access-log/stream`) — and it works **regardless of whether `--access-log` is set**,
since it reads the same in-memory broadcast the file writer does, not the file itself.

- Only one SSE connection is open at a time — switching Table ↔ Terminal closes whichever stream is
  active and opens the other.
- The panel **preloads the last 24 hours** of history on page load rather than starting empty.
- Lines are inserted as plain text (never HTML) since `Path` and `User-Agent` are attacker-controlled,
  and the panel caps at the last 100 lines.
- Long lines **scroll horizontally** instead of wrapping, like a real terminal.
- Auto-scroll-to-newest only continues while you're already at (or near) the bottom — scrolling up to
  read history pauses it automatically, independent of the manual Pause button.

---

<!-- Source: docs/configuration/metrics.md -->

# Prometheus Metrics

Coraza WAF Mod exposes a Prometheus exposition endpoint at **`/admin/metrics`**.

:::warning It is behind session-cookie auth, not HTTP Basic Auth
The endpoint is protected by the **same session-cookie admin authentication** as every other dashboard
page — it is **not** HTTP Basic Auth. A Prometheus `basic_auth:` scrape config therefore cannot
authenticate to it: an unauthenticated scrape is redirected (302) to the login page rather than
challenged for credentials. Scraping it currently requires either a code change to exempt the route,
or proxying through something that holds a valid admin session cookie.
:::

## Metric reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `coraza_http_requests_total` | Counter | `app`, `status` | Every request handled, by final HTTP status code. |
| `coraza_http_request_duration_seconds` | Histogram | `app` | Request handling latency, including WAF inspection and proxying. Default Prometheus buckets. |
| `coraza_ip_blocked_total` | Counter | `app` | Denied by the IP blocklist. |
| `coraza_geo_blocked_total` | Counter | `app`, `country` | Denied by a country/geo rule. |
| `coraza_waf_blocked_total` | Counter | `app`, `action` | Denied by Coraza, labeled by the matched rule's action. |
| `coraza_rate_limited_total` | Counter | `app` | Denied by the per-IP rate limiter. |
| `coraza_bot_challenged_total` | Counter | `app` | Redirected to the JS proof-of-work challenge. |
| `coraza_log_queue_depth` | Gauge | — | Current buffered request-log entries waiting to be written to SQLite (see [State & storage](/docs/overview/architecture#state--storage)). Read live on every scrape, not polled. |
| `coraza_services_total` | Gauge | — | Number of backend services currently configured. |
| `coraza_rate_limit_tracked_ips` | Gauge | — | Per-IP token buckets currently held in memory. |

Plus the standard Go runtime/process metrics (`go_*`, `process_*`) that `promhttp.Handler()` exposes
automatically.

:::note[Per-cause counters vs. adaptive-enforcement-triggered events]
`coraza_rate_limited_total` and `coraza_bot_challenged_total` increment for **both** a plain
rate-limit/challenge decision and one forced by
[adaptive enforcement](/docs/security/threat-score#adaptive-enforcement) — the metric doesn't
distinguish the two (the request log's `action` column does, via the `:adaptive` suffix).
:::

## Example output

```text
# HELP coraza_http_requests_total Total requests handled, labeled by app and final HTTP status code.
# TYPE coraza_http_requests_total counter
coraza_http_requests_total{app="api",status="200"} 18234
coraza_http_requests_total{app="api",status="403"} 112
# HELP coraza_waf_blocked_total Requests denied by the Coraza WAF, labeled by app and the matched rule's action.
# TYPE coraza_waf_blocked_total counter
coraza_waf_blocked_total{app="api",action="deny"} 47
# HELP coraza_log_queue_depth Current number of request-log entries buffered waiting to be written to SQLite.
# TYPE coraza_log_queue_depth gauge
coraza_log_queue_depth 0
```

For the live in-dashboard view of the same data, see the [dashboard home](/docs/configuration/dashboard)
(traffic and threat charts).

---

<!-- Source: docs/configuration/varnish.md -->

# Varnish Cache Integration

A per-service **Cache** toggle routes that service's traffic through a **Varnish** cache that sits
*behind* the WAF — a "loopback sandwich":

```
client → coraza-waf-mod (WAF-inspected) → varnishd (127.0.0.1:6081)
       → coraza-waf-mod cache-return listener (127.0.0.1:6082) → the real backend
```

Nothing reaches Varnish or the backend without first passing the full WAF pipeline.

## Turning it on

- **Per-service** — the **Cache** toggle in a service's Manage panel on `/admin/services` marks that
  service cacheable. See [Services](/docs/configuration/dashboard).
- **Global** — the **Varnish Cache** card on the Settings page turns the whole integration on or off
  with no restart (`POST /admin/settings/varnish` with `varnish_enabled`, `varnish_addr`). While off,
  every service proxies straight to its backend even if individually marked cacheable.

:::warning The Varnish listen address must be a loopback address
`varnish_addr` is validated: anything that is not a loopback address is rejected outright, because
that port would let clients reach Varnish (and the backend) without passing through the WAF pipeline.
:::

## The VCL is static

Varnish's config (`deploy/varnish/default.vcl`) has exactly **one hardcoded backend** — the
coraza-waf-mod cache-return listener. Backend selection for a cache miss happens back inside the WAF
process (it resolves the correct backend from the live service registry), **not** in Varnish. So
adding, editing, or removing a service never requires touching the VCL or reloading `varnishd`.

## Cache-poisoning defenses

- Spoofable headers (`X-Forwarded-Host`, `X-Original-URL`, etc.) are **stripped** before the request
  reaches Varnish.
- The cache hash is partitioned by a WAF-set `X-Cache-Service` header that clients cannot control.
- Both the VCL and the cache-return listener **reject any non-loopback peer**.
- Responses that set cookies are marked **uncacheable** by default, so private data is never served
  from cache to a different visitor (session-aware caching, below, is the opt-in exception).

## Session-aware caching (opt-in)

By default Varnish refuses to cache **any** response for a request that carries a cookie — the safe
default, but it means a service that always sets a session cookie never gets cached at all. Per
service, you can instead partition the cache by a named session cookie's value:

- Toggle **Cache by session** and set the **session cookie name** in the service's Manage panel
  (`POST /admin/services/cache-session/:id` with `session_enabled=1`, `session_cookie_name`). Both
  are required together — enabling without a name is rejected.
- The WAF hashes the named cookie's value (never forwards it raw) and sends it as `X-Cache-Session`,
  which Varnish folds into its cache hash — so two different sessions never see each other's cached
  response, and the raw session token never appears in Varnish's own logs.
- Session-partitioned entries get a hard **10-second TTL ceiling** regardless of the backend's
  `Cache-Control` — appropriate for live, personalized content, not a static asset.

## Cache tuning

Per service, you can override Varnish's default freshness behavior from the **Cache tuning** panel
(`POST /admin/services/cache-tuning/:id` with `ttl_floor`, `ttl_ceiling`, `grace`, `keep` — all
optional whole-second values; blank means "use the VCL default" below):

| Field | VCL default when unset | Effect |
|---|---|---|
| `ttl_floor` | `1h` (the VCL's built-in default TTL for static-looking responses) | Minimum time-to-live enforced even if the backend's `Cache-Control` asks for less. |
| `ttl_ceiling` | none | Maximum time-to-live enforced even if the backend asks for more. |
| `grace` | `30s` | How long a stale object may still be served — e.g. while a fresh copy is being fetched, or if the backend is briefly unreachable. |
| `keep` | `30s` | How much longer *after* grace expires a stale object is kept around for conditional revalidation before being evicted outright. |

A `ttl_floor` greater than a non-zero `ttl_ceiling` is rejected by the save handler.

## Purging

The **Purge** button on a service's row (`POST /admin/services/cache-purge/:id`) sends a `PURGE`
request straight to Varnish's client port over loopback — the same trust model as the cache-return
listener — and Varnish bans every cached object tagged with that service's name. Use it after a
backend deploy that changes content you know is stale in cache.

---

<!-- Source: docs/configuration/email-alerts.md -->

# Daily Report & Ban Alert Emails

Coraza WAF Mod sends two kinds of email via **Cloudflare Email Service** (SMTPS — no external SMTP
provider needed):

- **Daily traffic report** — sent just after local midnight, covering the completed day: total
  requests, blocked count, 403s, unique blocked IPs, and a per-stage breakdown.
- **Ban alert** — sent every time [autoban](/docs/security/blocking#automatic-ip-banning) permanently
  blocks an IP.

A ban is written to the blocklist regardless of whether email is configured or the send succeeds —
email is a notification, not a dependency.

## What's configurable

**Only the recipient list and the Cloudflare API token** are configurable, from the **Email Alerts**
card on the Settings page (`POST /admin/settings/email` with `email_enabled`, `email_to`,
`email_token`). Everything else is **fixed in code** and never appears in `config.yaml`, the binary,
or `install.sh`:

| | Value |
|---|---|
| SMTP endpoint | `smtp.mx.cloudflare.net:465` (implicit TLS — no STARTTLS) |
| SMTP username | the literal string `api_token` |
| SMTP password | your configured Cloudflare API token |
| Sender address | fixed in code (see `internal/notify/mailer/mailer.go`'s `Sender` constant) — allowlist it in your mail client if alerts land in spam |

Connecting on the implicit-TLS port means `net/smtp.PlainAuth` works even though the standard library
client doesn't natively speak implicit TLS — `smtp.NewClient` detects the already-TLS connection and
marks the session as secured before auth runs.

The token is stored in the database (meta keys `email_enabled`, `email_token`, `email_to`) and **never
echoed back to the UI** once saved, so on subsequent saves leave the token field blank to keep the
existing value.

Alerts arrive with a display name so they show up as *Coraza WAF Mod* in your inbox. Gmail strips
inline SVG from HTML email, so the logo badge in the template is built from plain HTML/CSS (a green
rounded square with three bars) rather than an SVG image.

## Daily report contents

| Field | Meaning |
|---|---|
| Total | All requests logged in the completed day. |
| Blocked | Requests denied by any pipeline stage. |
| 403s | Requests answered with HTTP 403. |
| Unique blocked IPs | Distinct client IPs with at least one blocked request. |
| Per-stage breakdown | WAF-blocked, IP-blocked, geo-blocked, rate-limited, and bot-challenged counts. |

## Verifying credentials

A **Send test report** button (`POST /admin/settings/email/test`) sends a report covering the last 24
hours immediately, using the currently *saved* configuration — so save your settings first, then test
to verify the credentials before turning the daily schedule on.

## Idempotent per day

Sends are **idempotent per day**: a restart around midnight neither duplicates nor skips the daily
report, and a failed send is retried on the next tick/restart rather than being marked as sent.

---

<!-- Source: docs/security/waf.md -->

# WAF Inspection (Coraza + OWASP CRS)

- Embeds **Coraza v3** with the **OWASP Core Rule Set (CRS)** compiled directly into the binary —
  there is nothing to download or mount.
- Out of the box it detects and blocks common attack classes: **SQL injection, XSS, remote code
  execution, path traversal, restricted-file access**, and **known scanner user agents**.
- Custom `.conf` rule files can be layered **on top of** the CRS by pointing the `--waf-rules` flag
  at a directory.
- WAF rules can be **individually disabled** from the dashboard (the engine reads the disabled-rule
  list from the database and rebuilds itself live), so you can silence a noisy rule without editing
  files or restarting.

:::warning[Important engine behavior]
The recommended Coraza config ships in `DetectionOnly` mode by default, and the project deliberately
enables blocking (`SecRuleEngine On`) **after** the CRS includes so that rules actually block rather
than merely score. This is handled internally.
:::

## The compiled directive set

Every engine (the shared default one, and any [per-service exception](#per-service-exceptions)
engine) is built from the same base directive block, with `SecRuleRemoveById` appended only when
there's a disabled-rule list to apply:

```apache
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit <configured limit, bytes>
SecRequestBodyNoFilesLimit 131072
SecDebugLogLevel 0
SecRuleRemoveById <space-separated rule IDs>   # only present if the disabled-rule list is non-empty
```

**Ordering matters and has bitten this project before:** `@coraza.conf-recommended` itself sets
`SecRuleEngine DetectionOnly`, and Coraza applies directives in the order they're parsed — so
`SecRuleEngine On` must come **after** the three `Include` lines, or every rule still matches and
scores but nothing is ever actually blocked (the request would be logged, but proxied through
anyway). If you point `--waf-rules` at a directory of custom `.conf` files, they're appended as one
more `Include "<dir>/*.conf"` directive **after** this block — so a custom rule file can still see
CRS's transformation/collection setup, and blocking is already turned on by the time it's parsed.

`SecResponseBodyAccess Off` means response bodies are never buffered/inspected — only requests are —
which keeps the WAF from adding latency to (or being confused by) large or streamed backend
responses.

## Disabling a noisy rule

<div className="doc-img">
  <img
    src="/img/docs/docs_waf_rules.png"
    alt="WAF Rules page showing the Disable Rule form with CRS Rule ID and reason fields, Top Firing Rules analytics table with hit counts, and the Disabled Rules list"
  />
</div>

The **WAF Rules** page (`/admin/waf-rules`) lists CRS rules. Disable a rule by ID with a reason
(`POST /admin/waf-rules/disable` with `rule_id`, `reason`) and re-enable it
(`DELETE /admin/waf-rules/:id`). The WAF engine rebuilds itself from the current disabled-rule list,
so the change is live — no restart. See the [dashboard walkthrough](/docs/configuration/dashboard).

## Per-service exceptions

By default, disabling a rule silences it for **every** service behind the WAF. That's the wrong
trade-off for a rule that's only noisy against one backend — for example, CRS rule `911100` ("Method
is not allowed by policy") blocks any request whose HTTP method isn't in CRS's default
`tx.allowed_methods` (`GET HEAD POST OPTIONS`), so a legitimate `PATCH`/`PUT`/`DELETE` to a REST API
gets blocked as a false positive. Disabling `911100` globally fixes that one API but also removes
HTTP-method enforcement for every other service on the WAF.

The **Scope** selector on the disable form fixes this: pick a specific service instead of `Global`,
and the exception applies **only to that backend** — every other service keeps enforcing the rule
normally.

Under the hood, scoped exceptions are stored in their own table
(`waf_service_rule_exceptions`, separate from the global `waf_disabled_rules` table, since the global
table's schema allows only one row per rule ID). Any service with at least one scoped exception gets
its **own compiled Coraza engine** — the global disabled-rule list plus that service's own exceptions
— built once per reload and swapped in behind the same lock as the shared default engine. Services
with no exceptions of their own keep using the shared default engine, so this costs nothing in memory
for a deployment that never uses the feature.

A **"Per-Service Exceptions"** card on the WAF Rules page lists every scoped exception (rule ID,
service, reason, when it was added) and lets you re-enable one
(`DELETE /admin/waf-rules/service/:id`). The existing "Disabled Rules" card and the "Top Firing
Rules" table's Active/Disabled badge only ever reflect the **global** list — a rule scoped to one
service is still shown as active globally, since conflating the two would be misleading.

## WAF detects but doesn't block?

Make sure you're on a normal build (blocking is enabled after the CRS includes by design), and check
whether the specific rule was disabled from the dashboard.

---

<!-- Source: docs/security/blocking.md -->

# IP & Geo Blocking

Three independent mechanisms feed the same IP block list, all enforced **early** in the pipeline
(before the WAF) and all hot-reloaded on change. Manage them from the dashboard — see
[Blocks](/docs/configuration/dashboard).

## IP blocklisting

- Manual **allow/block** rules for individual IPs (or CIDR ranges), managed from the dashboard.
- Exact-match enforcement evaluated very early in the pipeline (before geo and WAF) so blocked IPs
  are rejected cheaply.
- Augmented automatically by the [threat-intel sync](/docs/security/threat-intel-webhooks) feature —
  synced IPs flow into the same blocklist and take effect immediately via hot reload.
- Also populated automatically by the **autoban** system (see below).

## Automatic IP banning

The autoban engine watches the log fan-out pipeline and scores blocked events per client IP inside a
configurable **sliding time window**. When a single IP accumulates enough points, it is automatically
written as a permanent global block rule and the blocklist is hot-reloaded — no manual intervention
required.

### Scoring

| Event | Points |
|---|---|
| WAF block — critical class (SQLi, RCE, XSS, LFI, RFI rules) | **5** |
| WAF block — other rule | **2** |
| Rate-limited | **1** |
| Unsolved bot-challenge redirect ([see Bot Protection](/docs/security/bot-and-fingerprinting)) | **1** |
| Already-blocked traffic | **0** (banned IPs never score again) |

### Defaults and tuning

| Setting | Default | Notes |
|---|---|---|
| Enabled | **on** | Toggle from **IP Rules → Automatic banning** card |
| Score threshold | **10 points** | Ban triggers when an IP crosses this within the window |
| Window | **10 minutes** | Sliding window; resets per IP on each new event |

Threshold **10 / 10 min** is roughly two critical WAF hits, four generic WAF hits, or ten
rate-limited/challenged requests.

**Threshold guidance:**

- **Default (10 / 10 min)** is appropriate for most sites — an attacker running a SQLi scan hits
  threshold in two critical-class blocks (5 × 2 = 10).
- Raise to **20+** for sites that serve developer tools, SQL-heavy search forms, or shared-IP
  environments (universities, corporate NAT) to reduce false-positive bans.

### What happens on a ban

1. A permanent global `block` rule is written to `ip_rules` with a machine-stamped note (reason,
   score, timestamp).
2. The in-memory IP blocklist hot-reloads — subsequent requests from the IP are rejected immediately.
3. A **ban-alert email** is sent (if email alerts are configured) with the IP address, trigger reason,
   and timestamp.
4. The IP row in the **IP Rules** page shows an amber **Auto** badge and the ban reason.

### Exemptions & admin precedence

- **Private, loopback, link-local, and unspecified IPs are never auto-banned.**
- An existing admin rule (**allow** *or* **block**) for an IP always takes precedence: the autoban
  engine calls `GetIPRuleType` before scoring, and if a manual rule exists it leaves the IP untouched —
  your manual rules are never overwritten.

### Dashboard controls

The **Automatic banning** card on the **IP Rules** page (`/admin/ip-rules`) exposes:

- **Enable / disable** toggle (`POST /admin/ip-rules/autoban` with `autoban_enabled=1`).
- **Score threshold** and **window (minutes)** fields.

Changes take effect immediately via hot reload on the `Banner` subsystem.

## Geo / country blocking

- Country-level blocking using **MaxMind GeoLite2-Country**, with the database **bundled into the
  binary** — fresh installs block by country with **no MaxMind account or download step**.
- You can override the bundled database with a newer external `.mmdb` via the `--geo-db` flag.
- The client country is resolved from the [real client IP](/docs/security/trusted-proxy), so it works
  correctly behind Cloudflare or a trusted load balancer.

Enter a **2-letter ISO country code** (`RU`, `CN`, `US` — case-insensitive) and a rule type
(`block`/`allow`) on the **Geo Rules** page; the geo blocker reloads instantly.

---

<!-- Source: docs/security/bot-and-fingerprinting.md -->

# Bot Protection & Fingerprinting

## Bot protection & JS challenge

- Each request is scored **O(1) from headers only**: scanner user agents, HTTP-library user agents,
  and missing/suspicious headers each add to an anomaly score.
- **Trusted SEO/social crawlers** (Googlebot, Bingbot, Applebot, etc.) are detected first and
  **bypass scoring and the challenge entirely**.
- When bot protection is active, requests without a valid bypass cookie are redirected to a
  **JavaScript proof-of-work challenge** (`/_cz/challenge`) — a SHA-256 nonce that a real browser
  solves in under a second, then receives an HMAC-signed bypass cookie.
- **Per-service bot mode** overrides the global setting:
  - `inherit` — use the global setting.
  - `always` — challenge every non-trusted client regardless of score.
  - `off` — never challenge.

Tune the global challenger (enabled, threshold, TTL) under **Settings → Bot protection**
(`POST /admin/settings/bot`, meta keys `bot_enabled`/`bot_threshold`/`bot_ttl`, defaulting to
**disabled, threshold 8, TTL 3600s** if never configured), and set per-service overrides from each
service's Manage panel. See the [dashboard walkthrough](/docs/configuration/dashboard).

### How the proof-of-work challenge works

1. A challenged request is redirected to `GET /_cz/challenge?n=<nonce>&r=<original-path>&exp=<unix-ts>&sig=<hmac>`
   — the nonce, expiry (2-minute solve window), and original destination are all embedded in the
   URL and authenticated with an HMAC (`sig`) so the challenge page itself can't be forged or replayed
   past its window.
2. The page's JS brute-forces a `solution` integer such that
   `SHA-256(nonce + solution)`'s **first byte is `0x00`** — roughly 256 attempts on average, solved by
   a real browser in well under a second, deliberately far too cheap to meaningfully slow down a
   single request but expensive enough to filter `curl`/basic scrapers that never run the JS at all.
3. Concurrently, the page loads the vendored FingerprintJS bundle (`GET /_cz/fp.js` — vendored rather
   than fetched from the public CDN, since ad blockers and Brave/Firefox block it by default) to
   compute a browser visitor ID, and probes for automated-browser leakage (see below).
4. The page `POST`s `{nonce, exp, sig, solution, visitor_id, automation}` to `/_cz/verify`. The server
   re-checks the signature, the PoW solution, and that the nonce hasn't already been redeemed (each
   nonce mints at most one cookie — replaying a captured solve within its window gets a `403`), then
   refuses the cookie outright if any automation signal was reported (see below).
5. On success, a bypass cookie (`cz_bot_ok`, `HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS) is set:
   `<expiry_unix>.<visitor_id>.<hmac>` — the HMAC covers both the expiry and the visitor ID, so a
   client can't extend its own TTL or swap in a different visitor ID without invalidating the cookie.
   A legacy two-part `<expiry>.<hmac>` format (no visitor ID, pre-dating FingerprintJS integration) is
   still accepted so cookies issued before an upgrade stay valid until they naturally expire.

<div className="doc-img">
  <img
    src="/img/docs/docs_bot_protection.png"
    alt="Bot Protection settings panel showing the enable toggle, anomaly threshold field set to 8, and bypass cookie TTL field set to 3600 seconds"
  />
</div>

### Automated-browser detection

The challenge page also probes for **automated-browser leakage**: `navigator.webdriver`,
ChromeDriver's `cdc_`/`$cdc_` arrays, `domAutomationController`, Selenium / Puppeteer / Playwright /
PhantomJS / Nightmare globals, and `HeadlessChrome` in the User-Agent. Any hit is reported to the
server alongside the proof-of-work solution, and the server **refuses to issue the bypass cookie**
even when the PoW itself was solved correctly — so off-the-shelf browser-driven scanners (OWASP ZAP's
browser-driven scan mode, Selenium/Puppeteer/Playwright automation) stay stuck at the challenge
instead of earning a trusted session. Repeated unsolved challenge redirects also accrue points toward
an [automatic IP ban](/docs/security/blocking#automatic-ip-banning).

:::note This is client-side detection
A determined attacker who reads the challenge page's JS can strip the signals before submitting, so
it defeats off-the-shelf automation, not custom evasion.
:::

## JA4 / JA3 TLS fingerprinting

**JA4** (primary) and **JA3** (legacy) fingerprints are both computed at the **TLS handshake** —
before the HTTP request is even parsed — giving you a TLS-layer signal about the client that is
independent of headers and can't be spoofed by editing the User-Agent.

- Each fingerprint is looked up per request. If the connection came through Cloudflare, the `Cf-Ja4` /
  `Cf-Ja3-Fp` headers are used instead of a local computation, since Cloudflare already computed them
  at its edge.
- **JA4 sorts cipher suites and extensions before hashing**, so a client that randomizes handshake
  order per connection (a common scraper/bot evasion trick) still produces a stable fingerprint — this
  is why JA4 is the primary signal.

:::warning Do not build new detection logic on JA3
JA3's MD5 hash has no such sorting and is trivially evaded by reordering the handshake. It is retained
only for continuity with existing log data and external JA3-keyed threat feeds.
:::

### JA4 format

A JA4 hash looks like `t13d1516h2_8daaf6152771_02713d6af862` — three underscore-separated sections:

- **`a` (plaintext, human-readable)** — transport (`t`=TCP/`q`=QUIC), TLS version (`13`/`12`/…),
  whether SNI was present (`d`=yes/`i`=no), zero-padded cipher count, zero-padded extension count, and
  the first ALPN value's first+last character (`h2` above). Comparable at a glance even before the
  hashed sections are checked.
- **`b`** — a truncated SHA-256 over the sorted cipher suite list.
- **`c`** — a truncated SHA-256 over the sorted extension list (SNI and ALPN excluded from the hash
  input, though still counted in section `a`).

**GREASE values** ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) — the fake cipher/extension/
version IDs real browsers insert to force servers to tolerate unknown values) are filtered out of
every section before counting or hashing, so a client's GREASE randomization never perturbs its own
fingerprint.

The resolved JA4 hash appears in each request's [log detail view](/docs/configuration/dashboard)
alongside the country and ASN.

## ASN / organization lookup

A bundled **DB-IP ASN Lite** database (`//go:embed`-ed) provides in-process ASN / organization
lookup for client IPs — **no MaxMind account, no external service**. Attribution is in
`THIRD_PARTY_NOTICES.md`. The resolved ASN/organization appears in each request's
[log detail view](/docs/configuration/dashboard).

---

<!-- Source: docs/security/threat-score.md -->

# Threat Score & Adaptive Enforcement

## Unified per-IP threat score

Every logged request feeds a **composite 0–100 risk score** per client IP, combining signals that
would otherwise stay siloed in separate subsystems:

| Component | Weight | Source |
|---|---|---|
| Autoban's current point total for the IP | up to 40 | [Automatic IP banning](/docs/security/blocking#automatic-ip-banning)'s own sliding-window score |
| Bot-analysis score already on the request | up to 20 | [Bot protection](/docs/security/bot-and-fingerprinting) header scoring |
| ASN/hosting classification | flat 15 | A small heuristic over the bundled ASN database (allowlist + org-name keyword match), excluding Cloudflare's own ranges since the bot/challenge subsystem already trusts that traffic separately |
| Geo risk | flat 10 | Whether the resolved country has an admin-configured **block** [geo rule](/docs/security/blocking#geo--country-blocking) — reuses existing config, no new admin surface |
| JA4 repeat-offender history | up to 15 | Lifetime blocked-hit count for the client's [JA4](/docs/security/bot-and-fingerprinting) TLS fingerprint |

This is a **read model, not an enforcement mechanism** on its own — nothing in the scorer blocks or
challenges a request by itself. It only computes and persists the score (with its per-component
breakdown) so you can see *why* an IP looks risky.

Because scoring runs asynchronously, a few requests behind the one that triggered it, the score for a
given IP always reflects that IP's *previous* requests — never the one currently in flight. This is
the same one-request lag autoban's own ban already has.

**Where you see it:**

- A **"Score N"** badge on each row of the [IP Rules page](/docs/configuration/dashboard#ip-rules).
- A threat-score breakdown section in each request's [log detail view](/docs/configuration/dashboard#request-logs).

## Adaptive enforcement

Adaptive enforcement consumes the score above to **automatically** scale the global rate limit and
force a bot challenge for high-risk clients — the two levers that are cheap and fully reversible with
the current architecture. (Tiering Coraza's *paranoia level* per request was considered and
deliberately excluded: paranoia level is baked into a compiled WAF engine at build time with no
per-transaction override, so supporting it would mean holding multiple full-CRS engines resident in
memory at once — tracked as a separate follow-up, not built here.)

:::warning[Disabled by default]
Unlike autoban, adaptive enforcement starts **off**. It's a brand-new mechanism riding on a heuristic
score (the ASN classification, in particular, can misfire) and it includes a security-*loosening*
action — relaxing the rate limit for low-risk IPs — so look at real scores accumulating on the IP
Rules page for a while before opting in.
:::

**Two independently configurable thresholds**, so tightening the rate limit and forcing a challenge
don't have to happen at the same score:

| Setting | Default | Effect |
|---|---|---|
| High-risk threshold | `70` | Score at or above this tightens the global rate limit. |
| High-risk rate scale | `0.3` | Multiplier applied to rate + burst for high-risk IPs (e.g. cut to 30%). |
| Force-challenge threshold | `70` | A separate, typically **stricter** threshold — only past this does a high-risk client also get force-challenged, regardless of per-service bot mode. |
| Low-risk threshold | `10` | Score at or below this relaxes the global rate limit. |
| Low-risk rate scale | `1.5` | Multiplier for low-risk IPs (e.g. 150% of normal). Never forces a challenge. |

A scaled decision only ever touches the **global** rate limiter, not per-service limits, and a scale
that would floor the burst below 1 token is clamped to 1 — a scoring bug can reduce a client's
throughput but can never fully lock out traffic.

Since every decision re-reads the client's *current* score, adaptive enforcement is inherently
reversible: an IP whose score has since dropped is judged on its new score on the very next request,
unlike autoban's permanent block rule, which needs an explicit removal.

**Log transparency:** a block/challenge caused *only* by adaptive enforcement (not the plain rate
limit or per-service bot mode) is logged as `rate_limited:adaptive` / `bot_challenge:adaptive` instead
of the plain action string, so you can tell the two apart in the request log.

Configure both cards from **IP Rules → Adaptive enforcement** — see the
[dashboard walkthrough](/docs/configuration/dashboard#adaptive-enforcement).

---

<!-- Source: docs/security/threat-intel-webhooks.md -->

# Threat Intel & Webhooks

## Threat-intel auto-sync

- A background worker periodically downloads external **plain-text IP block lists**, parses out
  IP/CIDR tokens (ignoring `#`/`;` comments, capped at a 10 MiB read), and writes them into the
  database.
- The IP blocklist reads from the same store, so synced IPs take effect **immediately via hot
  reload** — no restart.
- A **"sync now"** button in the dashboard fetches a single source on demand.

Add a source on the **Threat Intel** page (`/admin/threat-intel`) with a **label**, a **URL** to a
plain-text IP/CIDR list, and a sync **interval (hours)**. Each row can be toggled, synced now, or
deleted. See the [dashboard walkthrough](/docs/configuration/dashboard).

## Webhook event delivery

- Forwards request events to a configured webhook endpoint, **fully asynchronously** — delivery runs
  on a background goroutine reading off a 500-entry buffered queue, so a slow or unreachable endpoint
  never blocks the logging pipeline. If the queue is ever full, new events are **dropped silently**
  rather than backing up the log worker.
- Each delivery is an `HTTP POST` with `Content-Type: application/json` and a 5-second client
  timeout. The body is the **full logged request row** (JSON-marshaled `storage.RequestLog` — the
  same fields as a log detail view: timestamp, app, IP, method, path, status, country, ASN, JA4, the
  matched WAF rule/action, etc.).
- Delivery is filtered by a configurable, comma-separated **event list** managed from the dashboard.
  If no events are selected it defaults to `blocked`.

  | Category | Matches |
  |---|---|
  | `blocked` | Any request the pipeline blocked (`entry.Blocked == true`) — IP/geo/WAF/rate-limit denials. |
  | `challenged` | Redirected to the bot challenge — matched by prefix, so both the plain `bot_challenge` action and the adaptive-enforcement-forced `bot_challenge:adaptive` variant count. |
  | `all` | Every request, including normally proxied ones. |

- **Authentication is a shared secret, not a computed signature.** If `webhook_secret` is set, every
  delivery carries it verbatim as an `X-WAF-Secret` header — the receiver should compare that header
  against its own copy of the secret (constant-time compare) rather than expect an HMAC over the
  body.

Configure it under **Settings → Webhooks** (`POST /admin/settings/webhook` with `webhook_url`,
`webhook_secret`, `webhook_enabled=1`, and one or more `webhook_events` checkboxes).

### Receiving a delivery

The row has **no JSON tags**, so it marshals with the Go struct's exact (capitalized) field names —
not `snake_case`:

```text
POST /your-endpoint HTTP/1.1
Content-Type: application/json
User-Agent: coraza-waf-mod/internal/notify/webhook
X-WAF-Secret: your-configured-secret

{
  "ID": 1042,
  "Timestamp": "2026-07-11T12:51:34Z",
  "AppName": "gemsofcongress",
  "RealIP": "203.0.113.10",
  "ProxyIP": "104.16.0.1",
  "Country": "US",
  "Method": "PATCH",
  "Host": "cdn.gemsofcongress.com",
  "Path": "/api/v1/posts/27",
  "Query": "",
  "Status": 403,
  "Blocked": true,
  "RuleID": 911100,
  "Action": "deny",
  "UserAgent": "node",
  "Duration": 4,
  "HeadersJSON": "{...}",
  "RequestID": "a1b2c3d4e5f6",
  "Proto": "HTTP/2.0",
  "TLSVersion": "TLS 1.3",
  "TLSCipher": "TLS_AES_128_GCM_SHA256",
  "TLSSNI": "cdn.gemsofcongress.com",
  "ASN": 13335,
  "Org": "Cloudflare, Inc.",
  "JA3Hash": "",
  "JA4": "t13d1516h2_8daaf6152771_02713d6af862",
  "VisitorID": "",
  "BotScore": 0
}
```

`HeadersJSON` is itself a JSON-encoded `map[string]string` of the original request headers — decode
it as a nested document if you need header-level detail.

A non-2xx response is logged server-side but **never retried** — treat the webhook as best-effort
notification, not a guaranteed-delivery queue.

---

<!-- Source: docs/security/trusted-proxy.md -->

# Trusted-Proxy / Real Client IP

The client IP used for blocklist, geo, rate limiting, and logging is resolved by precedence:

1. `CF-Connecting-IP` — **only** when the socket peer is in Cloudflare's published ranges.
2. `X-Forwarded-For` / `X-Real-IP` — **only** when the socket peer is in a configured trusted-proxy
   CIDR (`--trusted-proxies`).
3. Otherwise, the **raw socket peer address**.

**Forwarded headers are never trusted by default.** Without `--trusted-proxies`, a direct client
cannot forge its source IP to evade IP/geo blocks or reset its rate-limit bucket.

:::warning[All clients showing the same IP?]
If all clients appear to share one IP (and rate limiting blocks everyone), you're likely behind a
proxy or load balancer but haven't set `--trusted-proxies`, so the real client IP isn't being read
from `X-Forwarded-For`. Add the proxy's CIDR to `--trusted-proxies`. Conversely, if you set
`--trusted-proxies` too broadly while directly internet-facing, clients could spoof their IP — only
list CIDRs you actually trust.
:::

---

<!-- Source: docs/security/response-headers.md -->

# Security Response Headers

A global middleware sets browser-hardening headers on **every** response (blocked, admin, and
proxied alike):

- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- **HSTS** on TLS connections
- `X-WAF-Engine` identification header

The `Server` header on every response is forced to `Coraza WAF Mod`, overwriting whatever the
backend sent.

:::note[No `X-Protected-By` header]
An earlier version also sent an `X-Protected-By` header. It was removed to reduce WAF fingerprinting
via response headers — `X-WAF-Engine` is the only identification header left.
:::

---

<!-- Source: docs/troubleshooting.md -->

# Troubleshooting

**Dashboard shows a certificate warning.** Expected with a self-signed cert — add a browser
exception, or configure a domain + ACME from **Settings → TLS** to get a trusted Let's Encrypt cert.
See [TLS Setup](/docs/configuration/tls).

**ACME certificate isn't issued.** Ensure DNS for your domain points at the server, that ports 80
and 443 are reachable from the internet, and that you started the binary with both `--listen :80`
(for the HTTP-01 challenge) and `--listen-tls :443`.

**All clients share one IP / rate limiting blocks everyone.** You're likely behind a proxy or load
balancer but haven't set `--trusted-proxies`, so the real client IP isn't being read from
`X-Forwarded-For`. Add the proxy's CIDR to `--trusted-proxies`. Conversely, if you set
`--trusted-proxies` too broadly while directly internet-facing, clients could spoof their IP — only
list CIDRs you actually trust. See [Trusted Proxy & Real Client IP](/docs/security/trusted-proxy).

**WAF detects but doesn't block.** Make sure you're on a normal build (blocking is enabled after the
CRS includes by design). Check whether the specific rule was disabled from the dashboard. See
[WAF Inspection](/docs/security/waf).

**A backend can't be added.** The add wizard probes the backend first; if it's unreachable from the
WAF host, the save is rejected. Verify the backend URL and network path.

**Service won't start under systemd.** `sudo journalctl -u coraza-waf-mod -e` for the error. Common
causes: port already in use, missing `CAP_NET_BIND_SERVICE` (binding 80/443), or a bad `--db`/`--certs`
path the service user can't write.

**Logs growing too large.** Confirm the prune timer is active (`systemctl list-timers | grep coraza`)
or add a cron job calling `coraza-waf-mod prune`. See [Log Retention & Pruning](/docs/configuration/log-retention).

**REST API returns 401 or 429.** `401` means the `Authorization: Bearer <key>` header is missing,
malformed, or the key was revoked/never existed — create a new one from **Settings → API Keys**.
`429` means the calling IP crossed the same 5-failures-in-15-minutes lockout the dashboard login uses;
wait for the lockout to expire (the response includes the remaining time) rather than retrying
immediately. See [REST API](/docs/configuration/rest-api).

---

<!-- Source: docs/faq.md -->

# FAQ

**Do I need Docker?** No. A `Dockerfile` and `docker-compose.yml` exist for container-based local
development, but the primary distribution is a native binary + systemd.

**Do I need a database server?** No. All state is in a single SQLite file. Redis is optional and only
for multi-node rate limiting.

**Do I need a MaxMind account for geo blocking?** No. A GeoLite2-Country database is bundled. You can
optionally override it with a freshly downloaded `.mmdb` via `--geo-db`.

**Is there a config file?** Not for the running server — it's configured by CLI flags plus the
dashboard/database. (Older docs referencing `config.yaml` predate the move to flags.)

**Can I run multiple instances?** Yes, behind a load balancer. Use the **Redis** rate-limit backend
so the instances share one rate-limit view, and set `--trusted-proxies` to the load balancer's CIDR.

**Can I manage services/IP rules without the dashboard UI?** Yes — a bearer-token-authenticated
[REST API](/docs/configuration/rest-api) at `/admin/api/v1` covers services, IP rules, and bans, for
scripting and CI integrations. Create a key from **Settings → API Keys**.

**Can I disable a WAF rule for just one backend?** Yes — the disable form on the **WAF Rules** page
has a **Scope** selector; pick a service instead of Global. See
[Per-service exceptions](/docs/security/waf#per-service-exceptions).

**Where does it store data?** The SQLite DB at `--db` (installer: `/var/lib/coraza-waf-mod/waf.db`)
and TLS files under `--certs` (installer: `/var/lib/coraza-waf-mod/certs`).

**How do I reset the admin password?** Re-running `coraza-waf-mod setup` is idempotent and won't
overwrite an existing password; change it from **Settings** in the dashboard instead. (If locked out,
credentials live in the `waf.db` meta table.)


