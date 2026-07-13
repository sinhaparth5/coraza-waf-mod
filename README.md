<div align="center">
  <img src="static/imgs/readme-logo.svg" alt="Coraza WAF Mod" width="480">

  <br><br>

  [![Release](https://img.shields.io/github/v/release/sinhaparth5/coraza-waf-mod?label=release&color=2A9D8F)](https://github.com/sinhaparth5/coraza-waf-mod/releases/latest)
  [![CI](https://img.shields.io/github/actions/workflow/status/sinhaparth5/coraza-waf-mod/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white&color=2A9D8F)](https://github.com/sinhaparth5/coraza-waf-mod/actions/workflows/ci.yml)
  [![CodeQL](https://img.shields.io/github/actions/workflow/status/sinhaparth5/coraza-waf-mod/codeql.yml?branch=main&label=CodeQL&logo=github&logoColor=white&color=2A9D8F)](https://github.com/sinhaparth5/coraza-waf-mod/actions/workflows/codeql.yml)
  [![Go Version](https://img.shields.io/github/go-mod/go-version/sinhaparth5/coraza-waf-mod?label=go&logo=go&logoColor=white&color=00ADD8)](go.mod)
  [![License](https://img.shields.io/github/license/sinhaparth5/coraza-waf-mod?label=license&color=76C893)](LICENSE)
  [![Go Report Card](https://goreportcard.com/badge/github.com/sinhaparth5/coraza-waf-mod)](https://goreportcard.com/report/github.com/sinhaparth5/coraza-waf-mod)
</div>

A single-binary Web Application Firewall + reverse proxy for Go, built on [Coraza](https://github.com/corazawaf/coraza) and the OWASP Core Rule Set, with a built-in admin dashboard. It uses one binary, one SQLite file, CLI flags for bootstrap settings, and dashboard-managed runtime settings. There is no config file, external database, or Node toolchain. Docker is available for local development but is not required.

<div align="center">
  <img src="static/waf-flow-diagram.png" alt="Request flow: Client to Coraza WAF + Proxy to Backend App(s), with SQLite and the Admin Dashboard attached" width="760">
</div>

## Features

- **WAF protection:** Coraza v3 with the OWASP Core Rule Set embedded in the binary. It blocks SQLi, XSS, RCE, path traversal, restricted file access, and known scanner user agents out of the box. Custom `.conf` rules can be loaded on top of CRS.
- **Reverse proxy / multi-app routing:** route by Host header (virtual hosting) or by path prefix, with automatic prefix stripping like nginx `location`, to as many backend apps as you need.
- **IP & country blocking:** manual IP allow/block rules plus GeoIP2-based country blocking (MaxMind GeoLite2), with Cloudflare-aware real-IP extraction and opt-in trusted proxy CIDRs for `X-Forwarded-For` / `X-Real-IP`.
- **TLS:** plain HTTP, automatic Let's Encrypt certificates, or your own cert/key, globally or per service. Upload a cert or enable auto-issue for a backend from the dashboard.
- **Admin dashboard:** HTMX/Tailwind UI for live traffic and threat charts, filterable request logs with live tail, IP/geo rule management, and service management. Changes apply immediately, with no restart.
- **Prometheus metrics:** `/admin/metrics` exposes request volume, latency, and per-cause block counters (IP/geo/WAF) alongside Go runtime metrics. It sits behind the same session-cookie admin auth as the rest of the dashboard, not HTTP Basic Auth, so a scrape job needs a logged-in session cookie rather than a username/password pair.
- **SQLite storage:** request logs, IP/geo rules, services, and TLS state all live in one `waf.db` file. No Postgres, Redis, or MySQL to run.

## Installing

### Option A: native binary

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
```

This downloads the release binary for your architecture (amd64/arm64), verifies its SHA256 checksum, creates a dedicated non-root system user, installs a systemd unit, and starts the service. The user is named `coraza-waf-mod` and is granted only `CAP_NET_BIND_SERVICE`, so it can bind ports 80/443 without running as root. The installer prompts for an admin email and password, or generates credentials, then seeds them into the database with `coraza-waf-mod setup`.

Check it's running:

```bash
sudo systemctl status coraza-waf-mod
sudo journalctl -u coraza-waf-mod -f
```

There is no config file to edit. Installer settings are either flags in the systemd unit (`sudo systemctl cat coraza-waf-mod`) or database values managed from the dashboard. Data, certs, and `waf.db` live under `/var/lib/coraza-waf-mod/`.

#### Upgrading

Re-run the same command:

```bash
curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
```

The installer detects the existing binary at `/usr/local/bin/coraza-waf-mod` and switches to upgrade mode. It downloads and verifies the latest release, replaces the binary, rewrites the systemd units, and restarts the service. It skips the interactive prompts. Admin credentials and TLS certificates are never touched on upgrade. Pin a specific version with `curl -fsSL ... | sudo CORAZA_VERSION=v1.2.3 bash`.

### Option B: build from source

Requires Go 1.25+.

```bash
git clone https://github.com/sinhaparth5/coraza-waf-mod.git
cd coraza-waf-mod
make build      # go generate (minifies JS) + go build -> ./coraza-waf-mod

# Seed an admin account (password is read from stdin, not a flag):
echo "your-password" | ./coraza-waf-mod setup --admin-email you@example.com

./coraza-waf-mod   # defaults: --listen :8080 --db waf.db --certs ./certs
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
2. Before first login, seed an admin account with `coraza-waf-mod setup --admin-email you@example.com` (password read from stdin). `install.sh` does this for you interactively.
3. Open the admin dashboard at `http://<host>:<port>/admin` (the path is currently fixed at `/admin`) and log in with that email and password.
4. Add backend apps from **Services**: give each service a name, a match rule (Host or path Prefix), and a backend URL. The wizard checks that the backend is reachable before saving. Services live in the database, with no config-file seeding step.
5. Manage IP rules, country blocking, and request logs from their dashboard pages. Changes take effect immediately.
6. Optionally enable TLS per service from the **Manage** button on its row. Upload a cert, or turn on auto-issue after setting an ACME contact email from the Settings page or passing `--domain`/`--acme-email` to `coraza-waf-mod setup`.

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
