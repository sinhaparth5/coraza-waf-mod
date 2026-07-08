# Coraza WAF Mod

A single-binary Web Application Firewall + reverse proxy for Go, built on [Coraza](https://github.com/corazawaf/coraza) (OWASP CRS) with a built-in admin dashboard. No config file, no external database, no Node toolchain — one binary, one SQLite file, CLI flags for bootstrap settings, everything else from the dashboard. Docker is available for local development but isn't required.

```
[Client] → [Coraza WAF + Proxy] → [Backend App(s)]
                  ↕
            [SQLite DB]
                  ↕
           [Admin Dashboard]
```

## Features

- **WAF protection** — Coraza v3 with the OWASP Core Rule Set embedded in the binary. Blocks SQLi, XSS, RCE, path traversal, restricted file access, and known scanner user agents out of the box. Custom `.conf` rules can be loaded on top of CRS.
- **Reverse proxy / multi-app routing** — route by Host header (virtual hosting) or by path prefix (with automatic prefix stripping, like nginx `location`), to as many backend apps as you need.
- **IP & country blocking** — manual IP allow/block rules plus GeoIP2-based country blocking (MaxMind GeoLite2), with Cloudflare-aware real-IP extraction and opt-in trusted proxy CIDRs for `X-Forwarded-For` / `X-Real-IP`.
- **TLS** — plain HTTP, automatic Let's Encrypt certificates, or your own cert/key — globally and/or per individual service (upload a cert or enable auto-issue per backend from the dashboard).
- **Admin dashboard** — HTMX/Tailwind UI for live traffic & threat charts, filterable request logs with live tail, IP/geo rule management, and service (backend app) management — all changes apply immediately, no restart required.
- **Prometheus metrics** — `/admin/metrics` exposes request volume, latency, and per-cause block counters (IP/geo/WAF) alongside Go runtime metrics. It sits behind the same session-cookie admin auth as the rest of the dashboard (not HTTP Basic Auth), so a scrape job needs a way to carry a logged-in session cookie rather than a plain username/password.
- **Everything in SQLite** — request logs, IP/geo rules, services, and TLS state all live in one `waf.db` file. No Postgres/Redis/MySQL to stand up.

## Installing

### Option A — native binary (recommended)

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
```

This downloads the release binary for your architecture (amd64/arm64), verifies its SHA256 checksum, creates a dedicated non-root system user (`coraza-waf-mod`, granted only `CAP_NET_BIND_SERVICE` so it can bind ports 80/443 without running as root), interactively prompts for an admin email and password (or generates one) and seeds it into the database via `coraza-waf-mod setup`, installs a systemd unit that starts the binary with CLI flags, and starts the service.

Check it's running:

```bash
sudo systemctl status coraza-waf-mod
sudo journalctl -u coraza-waf-mod -f
```

There is no config file to edit — everything the installer set up is either a flag baked into the systemd unit (`sudo systemctl cat coraza-waf-mod` to see it) or a setting stored in the database and managed from the dashboard. Data, certs, and `waf.db` live under `/var/lib/coraza-waf-mod/`.

#### Upgrading

Re-run the same command:

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
```

The installer detects the existing binary at `/usr/local/bin/coraza-waf-mod` and switches to upgrade mode: it downloads and verifies the latest release, replaces the binary, rewrites the systemd units, and restarts the service — skipping the interactive prompts entirely. Admin credentials and TLS certificates are never touched on upgrade. Pin a specific version instead of always taking latest with `curl -fsSL ... | sudo CORAZA_VERSION=v1.2.3 bash`.

### Option B — build from source

Requires Go 1.25+.

```bash
git clone https://github.com/sinhaparth5/coraza-waf-mod.git
cd coraza-waf-mod
make build      # go generate (minifies JS) + go build -> ./coraza-waf-mod

# Seed an admin account (password is read from stdin, not a flag):
echo "your-password" | ./coraza-waf-mod setup --admin-email you@example.com

./coraza-waf-mod   # defaults: --listen :8080 --db waf.db --certs ./certs
```

`make run` builds and runs in one step (run `setup` first, at least once, so you can log in). Pure Go all the way through (the SQLite driver is `modernc.org/sqlite`, no CGO), so this builds cleanly with nothing but a Go toolchain. See `./coraza-waf-mod --help`-equivalent flags in `main.go`, or the flag table in `CLAUDE.md`, for every bootstrap option (`--listen-tls`, `--waf-rules`, `--geo-db`, `--retention`, `--tls-cert`/`--tls-key`, `--trusted-proxies`).

### Option C — cross-compiled release binaries

```bash
make dist        # cross-compiles Linux amd64/arm64 and Windows amd64 binaries, CGO_ENABLED=0
make checksums   # writes dist/checksums.txt
```

### Option D — Docker (local development)

```bash
docker compose run --rm waf setup --db /data/waf.db --admin-email you@example.com
docker compose up --build
```

`Dockerfile` (multi-stage, `scratch` final image) and `docker-compose.yml` are for local container development only — not the recommended production path (see Option A).

## Usage

1. Start the server (see Installing above) — there is no config file, only CLI flags for bootstrap settings.
2. Before first login, seed an admin account with `coraza-waf-mod setup --admin-email you@example.com` (password read from stdin). `install.sh` does this for you interactively.
3. Open the admin dashboard at `http://<host>:<port>/admin` (the path is currently fixed at `/admin`) and log in with that email and password.
4. Add backend apps from **Services**: give it a name, a match rule (Host or path Prefix), and a backend URL. The wizard checks the backend is reachable before saving. Services live entirely in the database — there's no config-file seeding step.
5. Manage IP rules, country blocking, and request logs from their respective dashboard pages — everything takes effect immediately.
6. Optionally enable TLS per service from the **Manage** button on its row (upload a cert, or turn on auto-issue — set an ACME contact email from the Settings page, or pass `--domain`/`--acme-email` to `coraza-waf-mod setup`).

### GeoIP setup (optional)

Country blocking uses the bundled MaxMind GeoLite2 Country database by default, so fresh Windows/Linux builds work without manually copying an `.mmdb` file. This product includes GeoLite Data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

To override the bundled database with a newer external copy:

1. Create a MaxMind account from the [GeoLite2 signup page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).
2. In the MaxMind account portal, generate a license key for database downloads.
3. Download `GeoLite2-Country` in `GeoIP2 Binary (.mmdb)` format, then extract `GeoLite2-Country.mmdb`.
4. Put the file somewhere readable by the service, for example:

```bash
sudo mkdir -p /var/lib/coraza-waf-mod
sudo cp GeoLite2-Country.mmdb /var/lib/coraza-waf-mod/
```

5. Point the binary at it with `--geo-db`:

```bash
./coraza-waf-mod --geo-db /var/lib/coraza-waf-mod/GeoLite2-Country.mmdb
```

(For a systemd install, add `--geo-db ...` to the `ExecStart=` line in the unit and `sudo systemctl daemon-reload && sudo systemctl restart coraza-waf-mod`.)

Leave `--geo-db` unset to use the bundled database. GeoLite users must keep the database updated; MaxMind requires old database versions to be replaced or destroyed within 30 days of a new release, so release builds should refresh the bundled `.mmdb` regularly.

## Development

```bash
make build   # build (runs go generate first — required after editing static/js/src/*.js)
make test    # go test ./...
make clean   # remove binary, minified JS, dist/
```

See `CLAUDE.md` for architecture notes if you're working on the codebase.
