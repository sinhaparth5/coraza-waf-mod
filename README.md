<div align="center">
  <img src="static/imgs/readme-logo.svg" alt="Palisade" width="480">

  <br><br>

  [![Release](https://img.shields.io/github/v/release/sinhaparth5/palisade-waf?label=release&color=2A9D8F)](https://github.com/sinhaparth5/palisade-waf/releases/latest)
  [![CI](https://img.shields.io/github/actions/workflow/status/sinhaparth5/palisade-waf/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&color=2A9D8F)](https://github.com/sinhaparth5/palisade-waf/actions/workflows/ci.yml)
  [![codecov](https://codecov.io/gh/sinhaparth5/palisade-waf/graph/badge.svg)](https://codecov.io/gh/sinhaparth5/palisade-waf)
  [![CodeQL](https://img.shields.io/github/actions/workflow/status/sinhaparth5/palisade-waf/codeql.yml?branch=main&label=CodeQL&logo=github&logoColor=white&color=2A9D8F)](https://github.com/sinhaparth5/palisade-waf/actions/workflows/codeql.yml)
  [![Go Version](https://img.shields.io/github/go-mod/go-version/sinhaparth5/palisade-waf?label=go&logo=go&logoColor=white&color=00ADD8)](go.mod)
  [![License](https://img.shields.io/github/license/sinhaparth5/palisade-waf?label=license&color=76C893)](LICENSE)
</div>

**Palisade** is a web application firewall you can `scp` to a server: a WAF and reverse proxy in a single Go binary, built on [OWASP Coraza](https://github.com/corazawaf/coraza) and the OWASP Core Rule Set, with a built-in admin dashboard. It uses one binary, one SQLite file, CLI flags for bootstrap settings, and dashboard-managed runtime settings. There is no config file, external database, or Node toolchain. Docker is available for local development but is not required.

<div align="center">
  <img src="static/waf-flow-diagram.png" alt="Request flow: Client to Palisade WAF + Proxy to Backend App(s), with SQLite and the Admin Dashboard attached" width="760">
</div>

## Features

- **WAF protection:** Coraza v3 with the OWASP Core Rule Set embedded in the binary. It blocks SQLi, XSS, RCE, path traversal, restricted file access, and known scanner user agents out of the box. Custom `.conf` rules can be loaded on top of CRS.
- **Reverse proxy / multi-app routing:** route by Host header (virtual hosting) or by path prefix, with automatic prefix stripping like nginx `location`, to as many backend apps as you need.
- **IP & country blocking:** manual IP allow/block rules plus GeoIP2-based country blocking (MaxMind GeoLite2), with Cloudflare-aware real-IP extraction and opt-in trusted proxy CIDRs for `X-Forwarded-For` / `X-Real-IP`.
- **TLS:** plain HTTP, automatic Let's Encrypt certificates, or your own cert/key, globally or per service. Upload a cert or enable auto-issue for a backend from the dashboard.
- **Admin dashboard:** HTMX/Tailwind UI for live traffic and threat charts, filterable request logs with live tail, IP/geo rule management, and service management. Changes apply immediately, with no restart.
- **Prometheus metrics:** `/admin/metrics` exposes request volume, latency, and per-cause block counters (IP/geo/WAF) alongside Go runtime metrics. For Prometheus, scrape `/admin/api/v1/metrics` with an API key from Settings (a read-only key is enough) via `authorization: { credentials: cwaf_… }`; the `/admin/metrics` path is for a logged-in browser session.
- **Health probes:** `/_cz/healthz` (process up) and `/_cz/readyz` (database reachable) for load balancers and orchestrators; the Docker image wires `palisade healthcheck` into its `HEALTHCHECK`.
- **SQLite storage:** request logs, IP/geo rules, services, and TLS state all live in one `waf.db` file. No Postgres, Redis, or MySQL to run.

## Installing

### Option A: native binary

```bash
curl -fsSL https://waf-install.astrareconslabs.com/palisade-waf/install.sh | sudo bash
```

This downloads the release binary for your architecture (amd64/arm64), verifies its SHA256 checksum, creates a dedicated non-root system user, installs a systemd unit, and starts the service. The user is named `palisade` and is granted only `CAP_NET_BIND_SERVICE`, so it can bind ports 80/443 without running as root. The installer prompts for an admin email and password, or generates credentials, then seeds them into the database with `palisade setup`.

Check it's running:

```bash
sudo systemctl status palisade
sudo journalctl -u palisade -f
```

There is no config file to edit. Installer settings are either flags in the systemd unit (`sudo systemctl cat palisade`) or database values managed from the dashboard. Data, certs, and `waf.db` live under `/var/lib/palisade/`.

#### Upgrading

Re-run the same command:

```bash
curl -fsSL https://waf-install.astrareconslabs.com/palisade-waf/install.sh | sudo bash
```

The installer detects the existing binary at `/usr/local/bin/palisade` and switches to upgrade mode. It downloads and verifies the latest release, replaces the binary, rewrites the systemd units, and restarts the service. It skips the interactive prompts. Admin credentials and TLS certificates are never touched on upgrade. Pin a specific version with `curl -fsSL ... | sudo CORAZA_VERSION=v1.2.3 bash`.

**Upgrading from 2.4.x or earlier (Coraza WAF Mod):** the same command migrates automatically. It stops the old `coraza-waf-mod` service, moves `/var/lib/coraza-waf-mod`, `/etc/coraza-waf-mod` and `/var/log/coraza` to `/var/lib/palisade`, `/etc/palisade` and `/var/log/palisade`, renames the service user, and installs the `palisade` binary and `palisade` systemd units. Your database, admin account, certificates and encryption key carry over unchanged. Update anything that references the old access-log path (fail2ban, log shippers).

### Option B: build from source

Requires Go 1.27+.

```bash
git clone https://github.com/sinhaparth5/palisade-waf.git
cd palisade-waf
make build      # go generate (minifies JS) + go build -> ./palisade

# Seed an admin account (password is read from stdin, not a flag):
echo "your-password" | ./palisade setup --admin-email you@example.com

./palisade   # defaults: --listen :8080 --db waf.db --certs ./certs
```

`make run` builds and runs in one step. Run `setup` first, at least once, so you can log in. The project uses Go only; the SQLite driver is `modernc.org/sqlite`, with no CGO. See the flags in `main.go`, or the flag table in `CLAUDE.md`, for every bootstrap option (`--listen-tls`, `--waf-rules`, `--geo-db`, `--retention`, `--tls-cert`/`--tls-key`, `--trusted-proxies`).

### Option C: cross-compiled release binaries

```bash
make dist        # cross-compiles Linux amd64/arm64 and Windows amd64 binaries, CGO_ENABLED=0
make checksums   # writes dist/checksums.txt
```

### Option D: Docker for local development

```bash
docker compose run --rm waf setup --db /data/waf.db --admin-email you@example.com
docker compose up --build
```

`Dockerfile` (multi-stage, `scratch` final image) and `docker-compose.yml` are for local container development only. Use Option A for systemd-based installs.

## Usage

1. Start the server. There is no config file, only CLI flags for bootstrap settings.
2. Before first login, seed an admin account with `palisade setup --admin-email you@example.com` (password read from stdin). `install.sh` does this for you interactively.
3. Open the admin dashboard at `http://<host>:<port>/admin` (the path is currently fixed at `/admin`) and log in with that email and password.
4. Add backend apps from **Services**: give each service a name, a match rule (Host or path Prefix), and a backend URL. The wizard checks that the backend is reachable before saving. Services live in the database, with no config-file seeding step.
5. Manage IP rules, country blocking, and request logs from their dashboard pages. Changes take effect immediately.
6. Optionally enable TLS per service from the **Manage** button on its row. Upload a cert, or turn on auto-issue after setting an ACME contact email from the Settings page or passing `--domain`/`--acme-email` to `palisade setup`.

### GeoIP setup (optional)

Country blocking uses the bundled MaxMind GeoLite2 Country database by default, so fresh Windows/Linux builds work without manually copying an `.mmdb` file. This product includes GeoLite Data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

To override the bundled database with a newer external copy:

1. Create a MaxMind account from the [GeoLite2 signup page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).
2. In the MaxMind account portal, generate a license key for database downloads.
3. Download `GeoLite2-Country` in `GeoIP2 Binary (.mmdb)` format, then extract `GeoLite2-Country.mmdb`.
4. Put the file somewhere readable by the service, for example:

```bash
sudo mkdir -p /var/lib/palisade
sudo cp GeoLite2-Country.mmdb /var/lib/palisade/
```

5. Point the binary at it with `--geo-db`:

```bash
./palisade --geo-db /var/lib/palisade/GeoLite2-Country.mmdb
```

(For a systemd install, add `--geo-db ...` to the `ExecStart=` line in the unit and `sudo systemctl daemon-reload && sudo systemctl restart palisade`.)

Leave `--geo-db` unset to use the bundled database. GeoLite users must keep the database updated; MaxMind requires old database versions to be replaced or destroyed within 30 days of a new release, so release builds should refresh the bundled `.mmdb` regularly.

## Development

```bash
make build   # build (runs go generate first — required after editing static/js/src/*.js)
make test    # go test ./...
make clean   # remove binary, minified JS, dist/
```

See `CLAUDE.md` for architecture notes if you're working on the codebase.
