#!/usr/bin/env bash
# Coraza WAF Mod — single-line installer
#
# Usage (always installs the latest release):
#   curl -fsSL https://waf-install.astrareconslabs.com/coraza-waf-mod/install.sh | sudo bash
#
# Pin to a specific version:
#   curl -fsSL ... | sudo CORAZA_VERSION=v1.0.0 bash
#
# Private project — pass a personal access token:
#   curl -fsSL ... | sudo GITHUB_TOKEN=ghp_xxxx bash
#
# Dry-run (prints every action, writes nothing):
#   DRY_RUN=1 bash install.sh
#
# Re-running on an existing install is safe: upgrades the binary and restarts
# the service. Admin credentials and certificates are never overwritten on upgrade.
set -euo pipefail

# ── Terminal colors ─────────────────────────────────────────────────────────
# Off when stdout isn't a terminal (e.g. redirected to a log) or NO_COLOR is
# set (https://no-color.org). Every message goes through one of the helpers
# below so the whole script reads with one consistent voice: cyan steps,
# dim supporting detail, bold for values the script discovered or generated,
# yellow/red for things that need attention.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	C_RESET=$'\033[0m'
	C_BOLD=$'\033[1m'
	C_DIM=$'\033[2m'
	C_CYAN=$'\033[36m'
	C_GREEN=$'\033[32m'
	C_YELLOW=$'\033[33m'
	C_RED=$'\033[31m'
else
	C_RESET='' C_BOLD='' C_DIM='' C_CYAN='' C_GREEN='' C_YELLOW='' C_RED=''
fi

step()   { printf '%s%s==>%s %s\n' "$C_BOLD" "$C_CYAN" "$C_RESET" "$*"; }
detail() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
value()  { printf '    %s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
ok()     { printf '    %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()   { printf '    %s%sWARNING:%s %s\n' "$C_BOLD" "$C_YELLOW" "$C_RESET" "$*"; }
err()    { printf '%s%sERROR:%s %s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$*" >&2; }

# ── Project config ────────────────────────────────────────────────────────────
GITHUB_API="https://api.github.com"
GITHUB_REPO="sinhaparth5/coraza-waf-mod"
# ─────────────────────────────────────────────────────────────────────────────

DRY_RUN="${DRY_RUN:-0}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
CORAZA_VERSION="${CORAZA_VERSION:-}"

BINARY_NAME="coraza-waf-mod"
SERVICE_USER="coraza-waf-mod"
VAR_DIR="/var/lib/coraza-waf-mod"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
UNIT_PATH="/etc/systemd/system/${BINARY_NAME}.service"
PRUNE_SERVICE_PATH="/etc/systemd/system/${BINARY_NAME}-prune.service"
PRUNE_TIMER_PATH="/etc/systemd/system/${BINARY_NAME}-prune.timer"
CERT_FILE="${VAR_DIR}/certs/self-signed.crt"
KEY_FILE="${VAR_DIR}/certs/self-signed.key"
# Deliberately under /etc, outside ${VAR_DIR}: exfiltrating the data
# directory (or a waf.db backup) alone must not also hand over the key that
# decrypts the secrets stored inside it.
DB_KEY_FILE="/etc/${BINARY_NAME}/db.key"

if [ "$DRY_RUN" = "1" ]; then
	printf '%s%sDRY RUN%s — no files will be written and no commands executed.\n' "$C_BOLD" "$C_YELLOW" "$C_RESET"
	echo
fi

if [ "$DRY_RUN" != "1" ] && [ "$(id -u)" -ne 0 ]; then
	err "Run as root (e.g. with sudo)."
	exit 1
fi

case "$(uname -s)" in
	Linux) ;;
	*) err "Only Linux is supported by this installer."; exit 1 ;;
esac

case "$(uname -m)" in
	x86_64 | amd64)  ARCH="amd64" ;;
	aarch64 | arm64) ARCH="arm64" ;;
	*) err "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

API_BASE="${GITHUB_API}/repos/${GITHUB_REPO}"

# ── Helpers ───────────────────────────────────────────────────────────────────

curl_get() {
	if [ -n "$GITHUB_TOKEN" ]; then
		curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" "$@"
	else
		curl -fsSL "$@"
	fi
}

run() {
	if [ "$DRY_RUN" = "1" ]; then
		printf '  %s+%s %s\n' "$C_DIM" "$C_RESET" "$*"
	else
		"$@"
	fi
}

write_file() {
	local dest="$1"
	local content
	content="$(cat)"
	if [ "$DRY_RUN" = "1" ]; then
		printf '  %s+ write %s%s\n' "$C_DIM" "$dest" "$C_RESET"
	else
		printf '%s\n' "$content" >"${dest}"
	fi
}

# detect_public_ip: tries ipify → ifconfig.me → local hostname -I
detect_public_ip() {
	local ip
	ip=$(curl -fsSL --connect-timeout 4 https://api.ipify.org 2>/dev/null) \
		&& printf '%s' "$ip" && return
	ip=$(curl -fsSL --connect-timeout 4 https://ifconfig.me 2>/dev/null) \
		&& printf '%s' "$ip" && return
	ip=$(hostname -I 2>/dev/null | awk '{print $1}') \
		&& [ -n "$ip" ] && printf '%s' "$ip" && return
	printf '<your-server-ip>'
}

# ── Detect existing install ───────────────────────────────────────────────────

IS_UPGRADE=0
if [ -f "${INSTALL_PATH}" ]; then
	IS_UPGRADE=1
fi

# ── Detect existing database backend (upgrade only) ──────────────────────────
# The systemd unit is rewritten unconditionally on every run (see "Systemd
# units" below), so without this the ExecStart line would silently reset
# back to the hardcoded SQLite default on every upgrade, undoing a MySQL/
# Postgres switch made either interactively on a previous fresh install or
# later via the admin UI's Settings -> Database connection card. The unit
# file's own ExecStart line is the source of truth for "what's running now"
# — mirrors how the self-signed TLS cert flags are already preserved across
# upgrades further down this script.
EXISTING_DB_DRIVER=""
EXISTING_DB_DSN=""
if [ "$IS_UPGRADE" = "1" ] && [ -f "${UNIT_PATH}" ]; then
	EXISTING_EXEC_LINE="$(grep '^ExecStart=' "${UNIT_PATH}" | head -1)"
	EXISTING_DB_DRIVER="$(printf '%s' "$EXISTING_EXEC_LINE" | sed -n "s/.*--db-driver  *\([^ ]*\).*/\1/p")"
	EXISTING_DB_DSN="$(printf '%s' "$EXISTING_EXEC_LINE" | sed -n "s/.*--db  *'\([^']*\)'.*/\1/p")"
fi

# ── Detect latest release version ────────────────────────────────────────────

if [ -z "$CORAZA_VERSION" ]; then
	step "Detecting latest release..."
	CORAZA_VERSION=$(
		curl_get "${API_BASE}/releases/latest" \
		| grep -o '"tag_name":[[:space:]]*"[^"]*"' \
		| head -1 \
		| sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/'
	)
	if [ -z "$CORAZA_VERSION" ]; then
		err "Could not detect the latest release from GitHub."
		printf '  Set CORAZA_VERSION manually: CORAZA_VERSION=v1.0.0 bash install.sh\n' >&2
		exit 1
	fi
	printf '    Latest: %s%s%s\n' "$C_BOLD" "$CORAZA_VERSION" "$C_RESET"
fi

ASSET="${BINARY_NAME}-linux-${ARCH}"
DOWNLOAD_BASE="https://github.com/${GITHUB_REPO}/releases/download/${CORAZA_VERSION}"

if [ "$IS_UPGRADE" = "1" ]; then
	step "Upgrading ${BINARY_NAME} to ${CORAZA_VERSION} (linux/${ARCH})"
else
	step "Installing ${BINARY_NAME} ${CORAZA_VERSION} (linux/${ARCH})"
fi
echo

# ── Interactive setup (fresh install only) ────────────────────────────────────

ADMIN_EMAIL=""
ADMIN_PASSWORD=""
DOMAIN=""
USE_ACME=0

# Database backend — only ever asked on a fresh install. DB_DSN is computed
# later, once the binary is actually installed (it's built via the binary's
# own `build-dsn` subcommand so a password containing ":"/"@"/"/" gets
# escaped correctly instead of a shell string concatenation corrupting it).
# On upgrade, whatever was chosen before is read back from the existing
# systemd unit's ExecStart line (see "Detect existing database backend"
# below) instead of asked again, so re-running this installer never resets
# a MySQL/Postgres deployment back to the SQLite default.
DB_DRIVER="sqlite"
DB_DSN=""
DB_HOST=""
DB_PORT=""
DB_USER=""
DB_PASSWORD=""
DB_NAME=""
DB_SSLMODE=""

if [ "$IS_UPGRADE" = "0" ] && [ "$DRY_RUN" != "1" ]; then
	# When piped from curl, stdin is the pipe — reconnect to the terminal.
	if [ ! -t 0 ]; then
		exec < /dev/tty
	fi

	# ── Admin credentials ───────────────────────────────────────────────────
	step "Admin account setup"
	echo

	while true; do
		read -rp "${C_CYAN}  Admin email:${C_RESET} " ADMIN_EMAIL
		[ -n "$ADMIN_EMAIL" ] && break
		printf '  %sEmail cannot be empty.%s\n' "$C_RED" "$C_RESET"
	done

	while true; do
		read -rsp "${C_CYAN}  Password:${C_RESET} " ADMIN_PASSWORD
		echo
		read -rsp "${C_CYAN}  Confirm: ${C_RESET} " ADMIN_PASSWORD_CONFIRM
		echo
		if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] && [ -n "$ADMIN_PASSWORD" ]; then
			break
		elif [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
			printf "  %sPasswords don't match — try again.%s\n" "$C_RED" "$C_RESET"
		else
			printf '  %sPassword cannot be empty.%s\n' "$C_RED" "$C_RESET"
		fi
	done

	echo

	# ── HTTPS setup ─────────────────────────────────────────────────────────
	step "HTTPS setup"
	detail "A self-signed certificate will be generated for your server IP."
	detail "If you have a domain name, Let's Encrypt can issue a trusted cert instead."
	echo
	read -rp "${C_CYAN}  Domain name (leave empty to use self-signed for IP):${C_RESET} " DOMAIN

	if [ -n "$DOMAIN" ]; then
		USE_ACME=1
		detail "Let's Encrypt will provision a certificate for ${DOMAIN}."
		detail "Make sure DNS for ${DOMAIN} points to this server before starting."
	else
		detail "A self-signed certificate will be generated for your server IP."
		detail "Browsers will show a security warning — you can add an exception."
	fi
	echo

	# ── Database backend ────────────────────────────────────────────────────
	step "Database backend"
	detail "SQLite (default) needs nothing else — recommended unless you already"
	detail "run a shared/managed MySQL, MariaDB, or Postgres-compatible server."
	echo
	read -rp "${C_CYAN}  Use an external database instead of SQLite? [y/N]:${C_RESET} " USE_EXTERNAL_DB

	if [[ "$USE_EXTERNAL_DB" =~ ^[Yy] ]]; then
		while true; do
			read -rp "${C_CYAN}  Driver (mysql/postgres):${C_RESET} " DB_DRIVER
			case "$(printf '%s' "$DB_DRIVER" | tr '[:upper:]' '[:lower:]')" in
				mysql | mariadb | postgres | postgresql | cockroachdb | neon) break ;;
				*) printf '  %sEnter mysql or postgres.%s\n' "$C_RED" "$C_RESET" ;;
			esac
		done
		read -rp "${C_CYAN}  Host (hostname, IP, or Docker service name):${C_RESET} " DB_HOST
		read -rp "${C_CYAN}  Port (leave empty for the driver default):${C_RESET} " DB_PORT
		read -rp "${C_CYAN}  Username:${C_RESET} " DB_USER
		read -rsp "${C_CYAN}  Password:${C_RESET} " DB_PASSWORD
		echo
		read -rp "${C_CYAN}  Database name:${C_RESET} " DB_NAME
		read -rp "${C_CYAN}  SSL mode (leave empty for the driver default; Postgres/Neon/CockroachDB usually want 'require'):${C_RESET} " DB_SSLMODE
		echo
		detail "Connection details recorded — verified once the binary is installed below."
	else
		DB_DRIVER="sqlite"
	fi
	echo
elif [ "$DRY_RUN" = "1" ]; then
	ADMIN_EMAIL="admin@example.com"
	ADMIN_PASSWORD="<prompted-at-runtime>"
	DOMAIN=""
fi

# ── Detect server IP ──────────────────────────────────────────────────────────

step "Detecting server IP address..."
SERVER_IP="$(detect_public_ip)"
value "${SERVER_IP}"
echo

# ── Download & verify binary ──────────────────────────────────────────────────

if [ "$DRY_RUN" = "1" ]; then
	step "[DRY RUN] Would download and verify ${DOWNLOAD_BASE}/${ASSET}"
	echo
else
	WORKDIR="$(mktemp -d)"
	trap 'rm -rf "$WORKDIR"' EXIT

	step "Downloading ${ASSET}"
	curl_get "${DOWNLOAD_BASE}/${ASSET}" -o "${WORKDIR}/${ASSET}"
	curl_get "${DOWNLOAD_BASE}/checksums.txt" -o "${WORKDIR}/checksums.txt"

	step "Verifying SHA256"
	(cd "$WORKDIR" && sha256sum --check --ignore-missing checksums.txt)

	step "Installing to ${INSTALL_PATH}"
	install -m 0755 "${WORKDIR}/${ASSET}" "${INSTALL_PATH}"
fi

# ── Resolve database driver/DSN ───────────────────────────────────────────────
# Only now (binary installed) can build-dsn actually run. Three cases:
#   upgrade + a non-sqlite driver was already configured -> keep it verbatim
#   upgrade + sqlite (or an unrecognized/pre-existing unit) -> the one true
#     SQLite default path, same as every version of this installer has used
#   fresh install + external DB chosen above -> build the DSN now
if [ "$IS_UPGRADE" = "1" ]; then
	if [ -n "$EXISTING_DB_DRIVER" ] && [ "$EXISTING_DB_DRIVER" != "sqlite" ]; then
		DB_DRIVER="$EXISTING_DB_DRIVER"
		DB_DSN="$EXISTING_DB_DSN"
		step "Keeping existing database backend: ${DB_DRIVER}"
	else
		DB_DRIVER="sqlite"
		DB_DSN="${VAR_DIR}/waf.db"
	fi
elif [ "$DB_DRIVER" != "sqlite" ] && [ "$DRY_RUN" != "1" ]; then
	step "Building database connection string"
	# Password on stdin (printf is a shell builtin, so it never appears in
	# ps/argv), same pattern as the `setup` invocations below — build-dsn
	# deliberately has no --password flag.
	DB_DSN="$(printf '%s\n' "$DB_PASSWORD" \
		| "${INSTALL_PATH}" build-dsn \
			--driver "$DB_DRIVER" --host "$DB_HOST" --port "$DB_PORT" \
			--username "$DB_USER" --dbname "$DB_NAME" --sslmode "$DB_SSLMODE")"
	ok "Connection string built for ${DB_DRIVER}"
elif [ "$DRY_RUN" = "1" ] && [ "$DB_DRIVER" != "sqlite" ]; then
	DB_DSN="<built-from-prompted-values>"
else
	DB_DSN="${VAR_DIR}/waf.db"
fi

# ── System user ───────────────────────────────────────────────────────────────

step "Creating system user '${SERVICE_USER}'"
if [ "$DRY_RUN" = "1" ] || ! id "${SERVICE_USER}" >/dev/null 2>&1; then
	run useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
else
	detail "User already exists — skipping"
fi

# ── Directories ───────────────────────────────────────────────────────────────

step "Creating directories"
run mkdir -p "${VAR_DIR}/certs"
run chown -R "${SERVICE_USER}:${SERVICE_USER}" "${VAR_DIR}"

# ── DB secrets encryption key ─────────────────────────────────────────────────
# Passed to the server as --db-key-file: stored secrets in waf.db (TOTP
# secrets, Cloudflare email token, webhook/Redis credentials, challenge HMAC
# key) get sealed with AES-256-GCM, so a stolen DB file or backup doesn't
# yield live credentials. Never regenerated on upgrade — a new key would
# orphan every secret encrypted under the old one.

step "Ensuring DB secrets encryption key"
if [ -f "${DB_KEY_FILE}" ]; then
	detail "Key already exists — keeping it"
else
	run mkdir -p "$(dirname "${DB_KEY_FILE}")"
	if [ "$DRY_RUN" = "1" ]; then
		detail "[DRY RUN] Would generate ${DB_KEY_FILE}"
	else
		head -c 32 /dev/urandom | base64 >"${DB_KEY_FILE}"
	fi
	run chown "${SERVICE_USER}:${SERVICE_USER}" "${DB_KEY_FILE}"
	run chmod 400 "${DB_KEY_FILE}"
fi

# ── TLS certificate ───────────────────────────────────────────────────────────

TLS_FLAGS="--listen :80 --listen-tls :443"

if [ "$IS_UPGRADE" = "0" ] && [ "$DRY_RUN" != "1" ]; then
	if [ "$USE_ACME" = "0" ]; then
		# Self-signed cert keyed to the server's public IP address.
		# The binary's gencert subcommand generates it using the Go stdlib —
		# no openssl dependency needed.
		step "Generating self-signed certificate for ${SERVER_IP}"
		"${INSTALL_PATH}" gencert \
			--cert "${CERT_FILE}" \
			--key  "${KEY_FILE}"  \
			--hosts "${SERVER_IP}" \
			--days 3650
		chown "${SERVICE_USER}:${SERVICE_USER}" "${CERT_FILE}" "${KEY_FILE}"
		TLS_FLAGS="--listen :80 --listen-tls :443 --tls-cert ${CERT_FILE} --tls-key ${KEY_FILE}"
	else
		# ACME: cert is provisioned automatically on first HTTPS request.
		# Store the domain and admin email so startTLS includes it in the host policy.
		printf '%s\n' "${ADMIN_PASSWORD}" \
			| "${INSTALL_PATH}" setup \
				--db-driver "${DB_DRIVER}" --db "${DB_DSN}" \
				--admin-email "${ADMIN_EMAIL}" \
				--domain "${DOMAIN}" \
				--acme-email "${ADMIN_EMAIL}"
		[ "$DB_DRIVER" = "sqlite" ] && chown "${SERVICE_USER}:${SERVICE_USER}" "${DB_DSN}" 2>/dev/null || true
		# (No --tls-cert flags — ACME handles it)
	fi
elif [ "$DRY_RUN" = "1" ]; then
	step "[DRY RUN] Would generate self-signed cert at ${CERT_FILE}"
	TLS_FLAGS="--listen :80 --listen-tls :443 --tls-cert ${CERT_FILE} --tls-key ${KEY_FILE}"
elif [ "$IS_UPGRADE" = "1" ] && [ -f "${CERT_FILE}" ] && [ -f "${KEY_FILE}" ]; then
	# Upgrade of a self-signed install: the cert files only exist on the
	# non-ACME path, so keep passing them — otherwise the rewritten unit
	# would drop the fallback cert and break HTTPS-by-IP after restart.
	step "Keeping existing self-signed certificate"
	TLS_FLAGS="--listen :80 --listen-tls :443 --tls-cert ${CERT_FILE} --tls-key ${KEY_FILE}"
fi

# ── Seed admin credentials (non-ACME path / fresh install) ───────────────────

if [ "$IS_UPGRADE" = "0" ] && [ "$USE_ACME" = "0" ] && [ "$DRY_RUN" != "1" ]; then
	step "Seeding admin credentials"
	printf '%s\n' "${ADMIN_PASSWORD}" \
		| "${INSTALL_PATH}" setup \
			--db-driver "${DB_DRIVER}" --db "${DB_DSN}" \
			--admin-email "${ADMIN_EMAIL}"
	[ "$DB_DRIVER" = "sqlite" ] && chown "${SERVICE_USER}:${SERVICE_USER}" "${DB_DSN}" 2>/dev/null || true
fi

# ── Systemd units ─────────────────────────────────────────────────────────────

step "Installing systemd units"

write_file "${UNIT_PATH}" <<UNIT
[Unit]
Description=Coraza WAF Mod (WAF + reverse proxy)
Documentation=https://github.com/sinhaparth5/coraza-waf-mod
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${VAR_DIR}
ExecStart=${INSTALL_PATH} ${TLS_FLAGS} --db-driver ${DB_DRIVER} --db '${DB_DSN}' --certs ${VAR_DIR}/certs --retention 30 --db-key-file ${DB_KEY_FILE}
Restart=on-failure
RestartSec=5s

# Bind :80/:443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

write_file "${PRUNE_SERVICE_PATH}" <<UNIT
[Unit]
Description=Coraza WAF Mod — log retention prune (one-shot)

[Service]
Type=oneshot
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${VAR_DIR}
# --vacuum rebuilds the DB file after pruning so freed pages go back to the
# OS — a plain DELETE never shrinks a SQLite file, it only marks pages
# reusable inside it.
ExecStart=${INSTALL_PATH} prune --db-driver ${DB_DRIVER} --db '${DB_DSN}' --retention 30 --vacuum
UNIT

write_file "${PRUNE_TIMER_PATH}" <<UNIT
[Unit]
Description=Coraza WAF Mod — run log retention prune every 15 days

[Timer]
OnBootSec=15min
OnUnitActiveSec=15d
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# ── Enable & (re)start ────────────────────────────────────────────────────────

step "Enabling and starting ${BINARY_NAME}"
run systemctl daemon-reload
run systemctl enable "${BINARY_NAME}"
run systemctl restart "${BINARY_NAME}"
run systemctl enable --now "${BINARY_NAME}-prune.timer"

# ── Varnish cache layer (optional accelerator) ───────────────────────────────
# Installs and configures Varnish for the WAF's cache integration:
# client → WAF → varnishd (127.0.0.1:6081) → WAF cache-return (127.0.0.1:6082)
# → backend. The VCL is static (one fixed backend) and never needs editing
# when services change — everything is driven from the admin UI. Best-effort:
# a failure here never breaks the WAF install; caching just stays unavailable.

VARNISH_VCL_PATH="/etc/varnish/default.vcl"
VARNISH_OVERRIDE_DIR="/etc/systemd/system/varnish.service.d"

step "Setting up Varnish cache layer (optional)"

if ! command -v varnishd >/dev/null 2>&1; then
	detail "Varnish not found — installing..."
	if [ "$DRY_RUN" = "1" ]; then
		printf '  %s+%s (apt-get|dnf|yum) install -y varnish\n' "$C_DIM" "$C_RESET"
	elif command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq >/dev/null 2>&1 || true
		DEBIAN_FRONTEND=noninteractive apt-get install -y varnish >/dev/null 2>&1 \
			|| warn "apt-get install varnish failed — install it manually later (see deploy/varnish/README.md)"
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y varnish >/dev/null 2>&1 \
			|| warn "dnf install varnish failed — install it manually later (see deploy/varnish/README.md)"
	elif command -v yum >/dev/null 2>&1; then
		yum install -y varnish >/dev/null 2>&1 \
			|| warn "yum install varnish failed — install it manually later (see deploy/varnish/README.md)"
	else
		warn "no supported package manager found — install Varnish manually to use caching"
	fi
fi

if [ "$DRY_RUN" = "1" ] || command -v varnishd >/dev/null 2>&1; then
	VARNISHD_BIN="$(command -v varnishd 2>/dev/null || echo /usr/sbin/varnishd)"

	# Never clobber a hand-written VCL silently: anything not created by this
	# installer (including the stock package example) is backed up first.
	if [ "$DRY_RUN" != "1" ] && [ -f "$VARNISH_VCL_PATH" ] && ! grep -q "coraza-waf-mod" "$VARNISH_VCL_PATH"; then
		detail "Backing up existing VCL to ${VARNISH_VCL_PATH}.pre-coraza"
		run cp "$VARNISH_VCL_PATH" "${VARNISH_VCL_PATH}.pre-coraza"
	fi
	run mkdir -p /etc/varnish
	write_file "$VARNISH_VCL_PATH" <<'VCL'
vcl 4.1;

# Installed by the coraza-waf-mod installer. This file is static — adding,
# editing, or removing services in the WAF admin UI never requires touching
# it. Cache misses go back to the WAF's cache-return listener, which routes
# to the right backend from its database:
#
#   client -> coraza-waf-mod (:80/:443) -> varnishd (127.0.0.1:6081)
#          -> coraza-waf-mod cache-return (127.0.0.1:6082) -> backend

import std;

acl local_only {
    "127.0.0.1";
    "::1";
}

backend waf_return {
    .host = "127.0.0.1";
    .port = "6082";
    .connect_timeout        = 5s;
    .first_byte_timeout     = 15s;
    .between_bytes_timeout  = 10s;
}

sub vcl_recv {
    if (client.ip !~ local_only) {
        return (synth(403, "Forbidden"));
    }
    if (!req.http.X-Cache-Service) {
        return (synth(400, "Missing service tag"));
    }

    set req.backend_hint = waf_return;

    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Drop the WAF's challenge-bypass cookie so it can't fragment the cache.
    if (req.http.Cookie) {
        set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\s*)cz_bot_ok=[^;]*", "");
        if (req.http.Cookie ~ "^\s*$") {
            unset req.http.Cookie;
        }
    }

    # Static assets: cache aggressively, ignore cookies.
    if (req.url ~ "\.(png|jpg|jpeg|gif|webp|avif|css|js|mjs|ico|svg|woff2?|ttf|map)(\?.*)?$") {
        unset req.http.Cookie;
        return (hash);
    }

    # Authenticated / session traffic: never cache.
    if (req.http.Authorization || req.http.Cookie) {
        return (pass);
    }

    return (hash);
}

sub vcl_hash {
    # Partition the cache per service.
    hash_data(req.http.X-Cache-Service);
}

sub vcl_backend_response {
    if (beresp.http.Set-Cookie) {
        set beresp.uncacheable = true;
        return (deliver);
    }
    if (beresp.ttl < 120s && bereq.url ~ "\.(png|jpg|jpeg|gif|webp|avif|css|js|mjs|ico|svg|woff2?|ttf)(\?.*)?$") {
        set beresp.ttl = 1h;
    }
    set beresp.grace = 30s;
}

sub vcl_deliver {
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
}
VCL

	run mkdir -p "$VARNISH_OVERRIDE_DIR"
	write_file "${VARNISH_OVERRIDE_DIR}/coraza.conf" <<UNIT
# Installed by coraza-waf-mod install.sh: bind loopback only — Varnish sits
# behind the WAF and must never be reachable from outside this host.
# -F keeps varnishd in the foreground: the stock unit is Type=notify, so
# without it varnishd daemonizes, the main process exits 0, and systemd tears
# down the cgroup (SIGTERM) moments after start.
[Service]
ExecStart=
ExecStart=${VARNISHD_BIN} -F -a 127.0.0.1:6081 -f ${VARNISH_VCL_PATH} -s malloc,256m
UNIT

	run systemctl daemon-reload
	if [ "$DRY_RUN" = "1" ]; then
		run systemctl enable --now varnish
		run systemctl restart varnish
	else
		systemctl enable --now varnish >/dev/null 2>&1 || true
		systemctl restart varnish \
			|| warn "varnish failed to start — check: journalctl -u varnish"
	fi
	ok "Varnish ready on 127.0.0.1:6081 — turn it on in the admin UI:"
	detail "Settings → Varnish Cache, then toggle Cache per service."
else
	detail "Varnish unavailable — the WAF runs fine without it; caching stays off."
fi
echo

# ── Done ──────────────────────────────────────────────────────────────────────

INSTALLED_VERSION="$("${INSTALL_PATH}" --version 2>/dev/null || echo "${CORAZA_VERSION}")"

if [ "$USE_ACME" = "1" ]; then
	DASHBOARD_URL="https://${DOMAIN}/admin"
	CERT_NOTE="Let's Encrypt — issued automatically on first visit"
else
	DASHBOARD_URL="https://${SERVER_IP}/admin"
	CERT_NOTE="Self-signed — browser will warn once, add an exception"
fi

BOX_TITLE="✓ Installation complete"
[ "$IS_UPGRADE" = "1" ] && BOX_TITLE="✓ Upgrade complete"

# Label/value rows, built as plain strings first so the box can size itself
# to whatever this run actually produced (IP/domain length, custom binary
# name, a long email, ...) instead of a hand-counted fixed width that
# silently breaks alignment the moment a value runs long.
LABEL_FIELD_W=12
row() { printf '%-*s%s' "$LABEL_FIELD_W" "$1:" "$2"; }

ROWS=()
[ "$IS_UPGRADE" = "0" ] && ROWS+=("")
ROWS+=("$(row 'Version' "$INSTALLED_VERSION")")
if [ "$IS_UPGRADE" = "0" ]; then
	ROWS+=(
		"$(row 'Admin UI' "$DASHBOARD_URL")"
		"$(row 'Email' "$ADMIN_EMAIL")"
		"$(row 'Password' '(as entered above)')"
		"$(row 'TLS' "$CERT_NOTE")"
	)
fi
ROWS+=(
	""
	"$(row 'Service' "sudo systemctl status ${BINARY_NAME}")"
	"$(row 'Logs' "sudo journalctl -u ${BINARY_NAME} -f")"
)

CONTENT_W=${#BOX_TITLE}
for r in "${ROWS[@]}"; do
	[ "${#r}" -gt "$CONTENT_W" ] && CONTENT_W=${#r}
done
[ "$CONTENT_W" -lt 66 ] && CONTENT_W=66

printf -v BORDER '%*s' "$((CONTENT_W + 4))" ''
BORDER=${BORDER// /─}

# printf '%-*s' pads to a *byte* count, not a character count — it comes up
# short whenever the string holds a multi-byte UTF-8 glyph (✓, the — in
# CERT_NOTE), which silently broke this box's right border before. Padding
# by hand against ${#text} (bash's char count, correct even for multi-byte
# glyphs) is what actually keeps every row's border aligned.
pad_to() {
	local width="$1" text="$2" n
	n=$(( width - ${#text} ))
	[ "$n" -lt 0 ] && n=0
	printf '%s%*s' "$text" "$n" ''
}

# Colors only the fixed-width label field of each row. Padding is always
# computed on the plain (uncolored) string first, so splicing ANSI codes in
# afterwards never throws off the column count that keeps the box aligned.
box_row() {
	local plain="$1" padded label rest
	padded="$(pad_to "$CONTENT_W" "$plain")"
	if [ -z "$plain" ]; then
		printf '  %s│%s  %s  %s│%s\n' "$C_GREEN" "$C_RESET" "$padded" "$C_GREEN" "$C_RESET"
	else
		label="${padded:0:LABEL_FIELD_W}"
		rest="${padded:LABEL_FIELD_W}"
		printf '  %s│%s  %s%s%s%s  %s│%s\n' "$C_GREEN" "$C_RESET" "$C_CYAN" "$label" "$C_RESET" "$rest" "$C_GREEN" "$C_RESET"
	fi
}

echo
printf '  %s┌%s┐%s\n' "$C_GREEN" "$BORDER" "$C_RESET"
TITLE_PADDED="$(pad_to "$CONTENT_W" "$BOX_TITLE")"
printf '  %s│%s  %s%s%s%s  %s│%s\n' "$C_GREEN" "$C_RESET" "$C_BOLD" "$C_GREEN" "$TITLE_PADDED" "$C_RESET" "$C_GREEN" "$C_RESET"
for r in "${ROWS[@]}"; do
	box_row "$r"
done
printf '  %s└%s┘%s\n' "$C_GREEN" "$BORDER" "$C_RESET"
echo

if [ "$IS_UPGRADE" = "0" ]; then
	printf '  %sNext steps:%s\n' "$C_BOLD" "$C_RESET"
	printf '    %s1.%s Open %s\n' "$C_CYAN" "$C_RESET" "$DASHBOARD_URL"
	if [ "$USE_ACME" = "0" ]; then
		printf '    %s2.%s Accept the browser security warning (self-signed cert)\n' "$C_CYAN" "$C_RESET"
		printf '    %s3.%s Add a backend service under Services\n' "$C_CYAN" "$C_RESET"
		printf '    %s4.%s Switch to a trusted cert: Settings → TLS → enter your domain\n' "$C_CYAN" "$C_RESET"
	else
		printf '    %s2.%s The TLS certificate will be issued automatically on first visit\n' "$C_CYAN" "$C_RESET"
		printf '    %s3.%s Add a backend service under Services\n' "$C_CYAN" "$C_RESET"
	fi
	echo
fi
