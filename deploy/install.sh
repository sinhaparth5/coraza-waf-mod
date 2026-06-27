#!/usr/bin/env bash
# One-line installer for coraza-waf-mod:
#   curl -fsSL https://<your-host>/install.sh | sudo bash
#
# Dry-run (prints every action, writes nothing):
#   DRY_RUN=1 bash install.sh
#
# Downloads the release binary + checksums, verifies the SHA256, installs to
# /usr/local/bin, creates a dedicated system user, writes a systemd unit, and
# starts the service. Re-running is safe: it won't overwrite an existing
# config or clobber a running install's data.
set -euo pipefail

# ─── EDIT THIS ────────────────────────────────────────────────────────────────
# Where release binaries + checksums.txt are published. Must contain:
#   coraza-waf-mod-linux-amd64, coraza-waf-mod-linux-arm64, checksums.txt
# e.g. GitLab Release assets, a generic package registry, or your own CDN.
BASE_URL="${CORAZA_WAF_MOD_BASE_URL:-https://example.invalid/REPLACE_ME/releases/latest}"
# ───────────────────────────────────────────────────────────────────────────────

DRY_RUN="${DRY_RUN:-0}"
if [ "$DRY_RUN" = "1" ]; then
	echo "DRY RUN MODE — no files will be written and no commands will be executed."
	echo
fi

BINARY_NAME="coraza-waf-mod"
SERVICE_USER="coraza-waf-mod"
ETC_DIR="/etc/coraza-waf-mod"
VAR_DIR="/var/lib/coraza-waf-mod"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
UNIT_PATH="/etc/systemd/system/${BINARY_NAME}.service"
PRUNE_SERVICE_PATH="/etc/systemd/system/${BINARY_NAME}-prune.service"
PRUNE_TIMER_PATH="/etc/systemd/system/${BINARY_NAME}-prune.timer"

if [ "$DRY_RUN" != "1" ] && [ "$(id -u)" -ne 0 ]; then
	echo "Run as root (e.g. with sudo)." >&2
	exit 1
fi

case "$(uname -s)" in
Linux) ;;
*)
	echo "Only Linux is supported by this installer." >&2
	exit 1
	;;
esac

case "$(uname -m)" in
x86_64 | amd64) ARCH="amd64" ;;
aarch64 | arm64) ARCH="arm64" ;;
*)
	echo "Unsupported architecture: $(uname -m)" >&2
	exit 1
	;;
esac

ASSET="${BINARY_NAME}-linux-${ARCH}"

# run: execute a command normally, or just print it in dry-run mode.
run() {
	if [ "$DRY_RUN" = "1" ]; then
		echo "  + $*"
	else
		"$@"
	fi
}

# write_file DEST: read content from stdin (heredoc) and write to DEST,
# or show what would be written in dry-run mode.
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

# ── Download & install binary ─────────────────────────────────────────────────

if [ "$DRY_RUN" = "1" ]; then
	echo "==> [DRY RUN] Would download ${ASSET} and checksums.txt from:"
	echo "      ${BASE_URL}/${ASSET}"
	echo "      ${BASE_URL}/checksums.txt"
	echo "==> [DRY RUN] Would verify SHA256 and install binary to ${INSTALL_PATH}"
	echo
else
	WORKDIR="$(mktemp -d)"
	trap 'rm -rf "$WORKDIR"' EXIT

	echo "==> Downloading ${ASSET} and checksums.txt"
	curl -fsSL "${BASE_URL}/${ASSET}" -o "${WORKDIR}/${ASSET}"
	curl -fsSL "${BASE_URL}/checksums.txt" -o "${WORKDIR}/checksums.txt"

	echo "==> Verifying SHA256"
	(cd "$WORKDIR" && sha256sum --check --ignore-missing checksums.txt)

	echo "==> Installing binary to ${INSTALL_PATH}"
	install -m 0755 "${WORKDIR}/${ASSET}" "${INSTALL_PATH}"
fi

# ── System user ───────────────────────────────────────────────────────────────

echo "==> Creating system user '${SERVICE_USER}'"
if [ "$DRY_RUN" = "1" ] || ! id "${SERVICE_USER}" >/dev/null 2>&1; then
	run useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

# ── Directories ───────────────────────────────────────────────────────────────

echo "==> Creating ${ETC_DIR} and ${VAR_DIR}"
run mkdir -p "${ETC_DIR}" "${VAR_DIR}/certs"
run chown -R "${SERVICE_USER}:${SERVICE_USER}" "${VAR_DIR}"

# ── Config ────────────────────────────────────────────────────────────────────

if [ "$DRY_RUN" != "1" ] && [ -f "${ETC_DIR}/config.yaml" ]; then
	echo "==> ${ETC_DIR}/config.yaml already exists, leaving it untouched"
else
	echo "==> Writing ${ETC_DIR}/config.yaml"
	if [ "$DRY_RUN" = "1" ]; then
		ADMIN_PASSWORD="<generated-at-install-time>"
	else
		ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
	fi
	write_file "${ETC_DIR}/config.yaml" <<EOF
# Plain HTTP — handles Let's Encrypt ACME HTTP-01 challenges and redirects
# all other traffic to HTTPS. Must be :80 for ACME to work.
listen_addr:     ":80"

# HTTPS — activates TLS on port 443. Certificate config (ACME email,
# per-service certs) is managed from the admin UI, not this file.
listen_addr_tls: ":443"

tls:
  # Let's Encrypt cert cache. Must be writable by the service user.
  cache_dir: "${VAR_DIR}/certs"

geo:
  db_path: ""

waf:
  enabled: true
  rules_dir: ""

db:
  path: "${VAR_DIR}/waf.db"
  log_retention_days: 30

admin:
  path: "/admin"
  username: "admin"
  password: "${ADMIN_PASSWORD}"

apps: []
EOF
	run chown "${SERVICE_USER}:${SERVICE_USER}" "${ETC_DIR}/config.yaml"
	run chmod 0640 "${ETC_DIR}/config.yaml"
	if [ "$DRY_RUN" != "1" ]; then
		echo
		echo "    Admin login: admin / ${ADMIN_PASSWORD}"
		echo "    (saved in ${ETC_DIR}/config.yaml — this is the only time it's printed)"
		echo
	fi
fi

# ── Systemd units ─────────────────────────────────────────────────────────────

echo "==> Installing systemd unit to ${UNIT_PATH}"
write_file "${UNIT_PATH}" <<EOF
[Unit]
Description=Coraza WAF Mod (WAF + reverse proxy)
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${VAR_DIR}
ExecStart=${INSTALL_PATH} ${ETC_DIR}/config.yaml
Restart=on-failure
RestartSec=5s

# Binds :80/:443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo "==> Installing log retention prune timer (runs every 15 days)"
write_file "${PRUNE_SERVICE_PATH}" <<EOF
[Unit]
Description=Coraza WAF Mod log retention prune (one-shot)

[Service]
Type=oneshot
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${VAR_DIR}
ExecStart=${INSTALL_PATH} prune ${ETC_DIR}/config.yaml
EOF

write_file "${PRUNE_TIMER_PATH}" <<EOF
[Unit]
Description=Run Coraza WAF Mod log retention prune every 15 days

[Timer]
OnBootSec=15min
OnUnitActiveSec=15d
Persistent=true

[Install]
WantedBy=timers.target
EOF

# ── Start service ─────────────────────────────────────────────────────────────

echo "==> Starting ${BINARY_NAME}"
run systemctl daemon-reload
run systemctl enable "${BINARY_NAME}"
run systemctl restart "${BINARY_NAME}"
run systemctl enable --now "${BINARY_NAME}-prune.timer"

echo
echo "Done."
echo
echo "Service status:"
echo "    sudo systemctl status ${BINARY_NAME}"
echo "    sudo journalctl -u ${BINARY_NAME} -f"
echo "    sudo systemctl list-timers ${BINARY_NAME}-prune.timer"
echo
echo "Next step — enable HTTPS (Let's Encrypt):"
echo "    1. Make sure ports 80 and 443 are open in your firewall/security group"
echo "    2. Open http://<your-server-ip>/admin  (HTTP works; HTTPS needs a cert first)"
echo "    3. Log in with the admin credentials printed above"
echo "    4. Go to Settings → TLS, enter your email and set each service to 'auto' TLS"
echo "    5. Certs are issued automatically; HTTP redirects to HTTPS from that point on"
