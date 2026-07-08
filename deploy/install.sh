#!/usr/bin/env bash
# Coraza WAF Mod — single-line installer
#
# Usage (always installs the latest release):
#   curl -fsSL https://raw.githubusercontent.com/sinhaparth5/coraza-waf-mod/main/deploy/install.sh | sudo bash
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

if [ "$DRY_RUN" = "1" ]; then
	echo "DRY RUN MODE — no files will be written and no commands executed."
	echo
fi

if [ "$DRY_RUN" != "1" ] && [ "$(id -u)" -ne 0 ]; then
	echo "Run as root (e.g. with sudo)." >&2
	exit 1
fi

case "$(uname -s)" in
	Linux) ;;
	*) echo "Only Linux is supported by this installer." >&2; exit 1 ;;
esac

case "$(uname -m)" in
	x86_64 | amd64)  ARCH="amd64" ;;
	aarch64 | arm64) ARCH="arm64" ;;
	*) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
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
		echo "  + $*"
	else
		"$@"
	fi
}

write_file() {
	local dest="$1"
	local content
	content="$(cat)"
	if [ "$DRY_RUN" = "1" ]; then
		echo "  + write ${dest}:"
		printf '%s\n' "$content" | sed 's/^/      /'
		echo
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

# ── Detect latest release version ────────────────────────────────────────────

if [ -z "$CORAZA_VERSION" ]; then
	echo "==> Detecting latest release..."
	CORAZA_VERSION=$(
		curl_get "${API_BASE}/releases/latest" \
		| grep -o '"tag_name":[[:space:]]*"[^"]*"' \
		| head -1 \
		| sed 's/"tag_name":[[:space:]]*"\([^"]*\)"/\1/'
	)
	if [ -z "$CORAZA_VERSION" ]; then
		echo "ERROR: Could not detect the latest release from GitHub." >&2
		echo "  Set CORAZA_VERSION manually: CORAZA_VERSION=v1.0.0 bash install.sh" >&2
		exit 1
	fi
	echo "    Latest: ${CORAZA_VERSION}"
fi

ASSET="${BINARY_NAME}-linux-${ARCH}"
DOWNLOAD_BASE="https://github.com/${GITHUB_REPO}/releases/download/${CORAZA_VERSION}"

if [ "$IS_UPGRADE" = "1" ]; then
	echo "==> Upgrading ${BINARY_NAME} to ${CORAZA_VERSION} (linux/${ARCH})"
else
	echo "==> Installing ${BINARY_NAME} ${CORAZA_VERSION} (linux/${ARCH})"
fi
echo

# ── Interactive setup (fresh install only) ────────────────────────────────────

ADMIN_EMAIL=""
ADMIN_PASSWORD=""
DOMAIN=""
USE_ACME=0

if [ "$IS_UPGRADE" = "0" ] && [ "$DRY_RUN" != "1" ]; then
	# When piped from curl, stdin is the pipe — reconnect to the terminal.
	if [ ! -t 0 ]; then
		exec < /dev/tty
	fi

	# ── Admin credentials ───────────────────────────────────────────────────
	echo "==> Admin account setup"
	echo

	while true; do
		read -rp "  Admin email: " ADMIN_EMAIL
		[ -n "$ADMIN_EMAIL" ] && break
		echo "  Email cannot be empty."
	done

	while true; do
		read -rsp "  Password: " ADMIN_PASSWORD
		echo
		read -rsp "  Confirm:  " ADMIN_PASSWORD_CONFIRM
		echo
		if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] && [ -n "$ADMIN_PASSWORD" ]; then
			break
		elif [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
			echo "  Passwords don't match — try again."
		else
			echo "  Password cannot be empty."
		fi
	done

	echo

	# ── HTTPS setup ─────────────────────────────────────────────────────────
	echo "==> HTTPS setup"
	echo "    A self-signed certificate will be generated for your server IP."
	echo "    If you have a domain name, Let's Encrypt can issue a trusted cert instead."
	echo
	read -rp "  Domain name (leave empty to use self-signed for IP): " DOMAIN

	if [ -n "$DOMAIN" ]; then
		USE_ACME=1
		echo "    Let's Encrypt will provision a certificate for ${DOMAIN}."
		echo "    Make sure DNS for ${DOMAIN} points to this server before starting."
	else
		echo "    A self-signed certificate will be generated for your server IP."
		echo "    Browsers will show a security warning — you can add an exception."
	fi
	echo
elif [ "$DRY_RUN" = "1" ]; then
	ADMIN_EMAIL="admin@example.com"
	ADMIN_PASSWORD="<prompted-at-runtime>"
	DOMAIN=""
fi

# ── Detect server IP ──────────────────────────────────────────────────────────

echo "==> Detecting server IP address..."
SERVER_IP="$(detect_public_ip)"
echo "    ${SERVER_IP}"
echo

# ── Download & verify binary ──────────────────────────────────────────────────

if [ "$DRY_RUN" = "1" ]; then
	echo "==> [DRY RUN] Would download and verify ${DOWNLOAD_BASE}/${ASSET}"
	echo
else
	WORKDIR="$(mktemp -d)"
	trap 'rm -rf "$WORKDIR"' EXIT

	echo "==> Downloading ${ASSET}"
	curl_get "${DOWNLOAD_BASE}/${ASSET}" -o "${WORKDIR}/${ASSET}"
	curl_get "${DOWNLOAD_BASE}/checksums.txt" -o "${WORKDIR}/checksums.txt"

	echo "==> Verifying SHA256"
	(cd "$WORKDIR" && sha256sum --check --ignore-missing checksums.txt)

	echo "==> Installing to ${INSTALL_PATH}"
	install -m 0755 "${WORKDIR}/${ASSET}" "${INSTALL_PATH}"
fi

# ── System user ───────────────────────────────────────────────────────────────

echo "==> Creating system user '${SERVICE_USER}'"
if [ "$DRY_RUN" = "1" ] || ! id "${SERVICE_USER}" >/dev/null 2>&1; then
	run useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
else
	echo "    User already exists — skipping"
fi

# ── Directories ───────────────────────────────────────────────────────────────

echo "==> Creating directories"
run mkdir -p "${VAR_DIR}/certs"
run chown -R "${SERVICE_USER}:${SERVICE_USER}" "${VAR_DIR}"

# ── TLS certificate ───────────────────────────────────────────────────────────

TLS_FLAGS="--listen :80 --listen-tls :443"

if [ "$IS_UPGRADE" = "0" ] && [ "$DRY_RUN" != "1" ]; then
	if [ "$USE_ACME" = "0" ]; then
		# Self-signed cert keyed to the server's public IP address.
		# The binary's gencert subcommand generates it using the Go stdlib —
		# no openssl dependency needed.
		echo "==> Generating self-signed certificate for ${SERVER_IP}"
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
				--db "${VAR_DIR}/waf.db" \
				--admin-email "${ADMIN_EMAIL}" \
				--domain "${DOMAIN}" \
				--acme-email "${ADMIN_EMAIL}"
		chown "${SERVICE_USER}:${SERVICE_USER}" "${VAR_DIR}/waf.db" 2>/dev/null || true
		# (No --tls-cert flags — ACME handles it)
	fi
elif [ "$DRY_RUN" = "1" ]; then
	echo "==> [DRY RUN] Would generate self-signed cert at ${CERT_FILE}"
	TLS_FLAGS="--listen :80 --listen-tls :443 --tls-cert ${CERT_FILE} --tls-key ${KEY_FILE}"
elif [ "$IS_UPGRADE" = "1" ] && [ -f "${CERT_FILE}" ] && [ -f "${KEY_FILE}" ]; then
	# Upgrade of a self-signed install: the cert files only exist on the
	# non-ACME path, so keep passing them — otherwise the rewritten unit
	# would drop the fallback cert and break HTTPS-by-IP after restart.
	echo "==> Keeping existing self-signed certificate"
	TLS_FLAGS="--listen :80 --listen-tls :443 --tls-cert ${CERT_FILE} --tls-key ${KEY_FILE}"
fi

# ── Seed admin credentials (non-ACME path / fresh install) ───────────────────

if [ "$IS_UPGRADE" = "0" ] && [ "$USE_ACME" = "0" ] && [ "$DRY_RUN" != "1" ]; then
	echo "==> Seeding admin credentials"
	printf '%s\n' "${ADMIN_PASSWORD}" \
		| "${INSTALL_PATH}" setup \
			--db "${VAR_DIR}/waf.db" \
			--admin-email "${ADMIN_EMAIL}"
	chown "${SERVICE_USER}:${SERVICE_USER}" "${VAR_DIR}/waf.db" 2>/dev/null || true
fi

# ── Systemd units ─────────────────────────────────────────────────────────────

echo "==> Installing systemd units"

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
ExecStart=${INSTALL_PATH} ${TLS_FLAGS} --db ${VAR_DIR}/waf.db --certs ${VAR_DIR}/certs --retention 30
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
ExecStart=${INSTALL_PATH} prune --db ${VAR_DIR}/waf.db --retention 30
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

echo "==> Enabling and starting ${BINARY_NAME}"
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

echo "==> Setting up Varnish cache layer (optional)"

if ! command -v varnishd >/dev/null 2>&1; then
	echo "    Varnish not found — installing..."
	if [ "$DRY_RUN" = "1" ]; then
		echo "  + (apt-get|dnf|yum) install -y varnish"
	elif command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq >/dev/null 2>&1 || true
		DEBIAN_FRONTEND=noninteractive apt-get install -y varnish >/dev/null 2>&1 \
			|| echo "    WARNING: apt-get install varnish failed — install it manually later (see deploy/varnish/README.md)"
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y varnish >/dev/null 2>&1 \
			|| echo "    WARNING: dnf install varnish failed — install it manually later (see deploy/varnish/README.md)"
	elif command -v yum >/dev/null 2>&1; then
		yum install -y varnish >/dev/null 2>&1 \
			|| echo "    WARNING: yum install varnish failed — install it manually later (see deploy/varnish/README.md)"
	else
		echo "    WARNING: no supported package manager found — install Varnish manually to use caching"
	fi
fi

if [ "$DRY_RUN" = "1" ] || command -v varnishd >/dev/null 2>&1; then
	VARNISHD_BIN="$(command -v varnishd 2>/dev/null || echo /usr/sbin/varnishd)"

	# Never clobber a hand-written VCL silently: anything not created by this
	# installer (including the stock package example) is backed up first.
	if [ "$DRY_RUN" != "1" ] && [ -f "$VARNISH_VCL_PATH" ] && ! grep -q "coraza-waf-mod" "$VARNISH_VCL_PATH"; then
		echo "    Backing up existing VCL to ${VARNISH_VCL_PATH}.pre-coraza"
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
			|| echo "    WARNING: varnish failed to start — check: journalctl -u varnish"
	fi
	echo "    Varnish ready on 127.0.0.1:6081 — turn it on in the admin UI:"
	echo "    Settings → Varnish Cache, then toggle Cache per service."
else
	echo "    Varnish unavailable — the WAF runs fine without it; caching stays off."
fi
echo

# ── Done ──────────────────────────────────────────────────────────────────────

INSTALLED_VERSION="$("${INSTALL_PATH}" --version 2>/dev/null || echo "${CORAZA_VERSION}")"

if [ "$USE_ACME" = "1" ]; then
	DASHBOARD_URL="https://${DOMAIN}/admin"
	CERT_NOTE="Let's Encrypt — cert auto-provisioned on first request"
else
	DASHBOARD_URL="https://${SERVER_IP}/admin"
	CERT_NOTE="Self-signed — accept the browser warning, or add an exception"
fi

echo
echo "  ┌──────────────────────────────────────────────────────────────────────┐"
if [ "$IS_UPGRADE" = "1" ]; then
echo "  │  Upgrade complete                                                    │"
printf "  │  Version:    %-55s │\n" "${INSTALLED_VERSION}"
else
echo "  │  Installation complete                                               │"
echo "  │                                                                      │"
printf "  │  Version:    %-55s │\n" "${INSTALLED_VERSION}"
printf "  │  Admin UI:   %-55s │\n" "${DASHBOARD_URL}"
printf "  │  Email:      %-55s │\n" "${ADMIN_EMAIL}"
echo "  │  Password:   (as entered above)                                     │"
printf "  │  TLS:        %-55s │\n" "${CERT_NOTE}"
fi
echo "  │                                                                      │"
echo "  │  Service:    sudo systemctl status ${BINARY_NAME}               │"
echo "  │  Logs:       sudo journalctl -u ${BINARY_NAME} -f                  │"
echo "  └──────────────────────────────────────────────────────────────────────┘"
echo
if [ "$IS_UPGRADE" = "0" ]; then
echo "  Next steps:"
echo "    1. Open ${DASHBOARD_URL}"
if [ "$USE_ACME" = "0" ]; then
echo "    2. Accept the browser security warning (self-signed cert)"
echo "    3. Add a backend service under Services"
echo "    4. Switch to a trusted cert: Settings → TLS → enter your domain"
else
echo "    2. The TLS certificate will be issued automatically on first visit"
echo "    3. Add a backend service under Services"
fi
echo
fi
