# Coraza WAF Mod

A single-binary Web Application Firewall + reverse proxy for Go, built on [Coraza](https://github.com/corazawaf/coraza) (OWASP CRS) with a built-in admin dashboard. No Docker, no external database, no Node toolchain — one binary, one SQLite file.

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
- **Prometheus metrics** — `/admin/metrics` exposes request volume, latency, and per-cause block counters (IP/geo/WAF) alongside Go runtime metrics, ready to scrape (uses the same admin credentials, since Prometheus scrape configs support basic auth natively).
- **Everything in SQLite** — request logs, IP/geo rules, services, and TLS state all live in one `waf.db` file. No Postgres/Redis/MySQL to stand up.

## Installing

### Option A — native binary (recommended)

```bash
curl -fsSL https://<wherever-this-is-published>/install.sh | sudo bash
```

This downloads the release binary for your architecture (amd64/arm64), verifies its SHA256 checksum, creates a dedicated non-root system user (`coraza-waf-mod`, granted only `CAP_NET_BIND_SERVICE` so it can bind ports 80/443 without running as root), writes a config to `/etc/coraza-waf-mod/config.yaml` with a freshly generated admin password (printed once), installs a systemd unit, and starts the service.

Check it's running:

```bash
sudo systemctl status coraza-waf-mod
sudo journalctl -u coraza-waf-mod -f
```

Config lives at `/etc/coraza-waf-mod/config.yaml` (see `deploy/config.yaml.example` for the annotated template) and data/certs at `/var/lib/coraza-waf-mod/`. Edit the config and `sudo systemctl restart coraza-waf-mod` to apply changes that aren't managed from the dashboard.

### Option B — build from source

Requires Go 1.25+.

```bash
git clone https://gitlab.com/sinhaparth5/coraza-waf-mod.git
cd coraza-waf-mod
make build      # go generate (minifies JS) + go build -> ./coraza-waf-mod
./coraza-waf-mod config.yaml
```

`make run` builds and runs in one step. Pure Go all the way through (the SQLite driver is `modernc.org/sqlite`, no CGO), so this builds cleanly with nothing but a Go toolchain.

### Option C — cross-compiled release binaries

```bash
make dist        # cross-compiles Linux amd64/arm64 and Windows amd64 binaries, CGO_ENABLED=0
make checksums   # writes dist/checksums.txt
```

## Usage

1. Edit `config.yaml` (see the comments inline) — set the listen address, TLS mode, GeoIP database path, and admin credentials.
2. Start the server: `./coraza-waf-mod config.yaml` (defaults to `config.yaml` in the working directory if no path is given).
3. Open the admin dashboard at `http://<host>:<port>/admin` (path is configurable via `admin.path`) and log in with the username/password from your config.
4. Add backend apps from **Services**: give it a name, a match rule (Host or path Prefix), and a backend URL. The wizard checks the backend is reachable before saving.
5. Manage IP rules, country blocking, and request logs from their respective dashboard pages — everything takes effect immediately.
6. Optionally enable TLS per service from the **Manage** button on its row (upload a cert, or turn on auto-issue if `tls.auto.email` is set in config).

The `apps:` list in `config.yaml` is only used to seed the database on first-ever startup — after that, **Services** in the dashboard is the source of truth for routing.

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

5. Set the path in `config.yaml`:

```yaml
geo:
  db_path: "/var/lib/coraza-waf-mod/GeoLite2-Country.mmdb"
```

Leave `geo.db_path` empty to use the bundled database. GeoLite users must keep the database updated; MaxMind requires old database versions to be replaced or destroyed within 30 days of a new release, so release builds should refresh the bundled `.mmdb` regularly.

## Development

```bash
make build   # build (runs go generate first — required after editing static/js/src/*.js)
make test    # go test ./...
make clean   # remove binary, minified JS, dist/
```

See `CLAUDE.md` for architecture notes if you're working on the codebase.
