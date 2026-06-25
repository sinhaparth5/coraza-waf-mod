#!/usr/bin/env bash
# One-line installer for coraza-waf-mod:
#   curl -fsSL https://<your-host>/install.sh | sudo bash
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

BINARY_NAME="coraza-waf-mod"
SERVICE_USER="coraza-waf-mod"
ETC_DIR="/etc/coraza-waf-mod"
VAR_DIR="/var/lib/coraza-waf-mod"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
UNIT_PATH="/etc/systemd/system/${BINARY_NAME}.service"
PRUNE_SERVICE_PATH="/etc/systemd/system/${BINARY_NAME}-prune.service"
PRUNE_TIMER_PATH="/etc/systemd/system/${BINARY_NAME}-prune.timer"

if [ "$(id -u)" -ne 0 ]; then
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
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> Downloading ${ASSET} and checksums.txt"
curl -fsSL "${BASE_URL}/${ASSET}" -o "${WORKDIR}/${ASSET}"
curl -fsSL "${BASE_URL}/checksums.txt" -o "${WORKDIR}/checksums.txt"

echo "==> Verifying SHA256"
(cd "$WORKDIR" && sha256sum --check --ignore-missing checksums.txt)

echo "==> Installing binary to ${INSTALL_PATH}"
install -m 0755 "${WORKDIR}/${ASSET}" "${INSTALL_PATH}"

echo "==> Creating system user '${SERVICE_USER}'"
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

echo "==> Creating ${ETC_DIR} and ${VAR_DIR}"
mkdir -p "${ETC_DIR}" "${VAR_DIR}/certs"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${VAR_DIR}"

if [ -f "${ETC_DIR}/config.yaml" ]; then
	echo "==> ${ETC_DIR}/config.yaml already exists, leaving it untouched"
else
	echo "==> Writing ${ETC_DIR}/config.yaml with a freshly generated admin password"
	ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
	cat >"${ETC_DIR}/config.yaml" <<EOF
listen_addr:     ":8080"
listen_addr_tls: ":443"

tls:
  mode: "off"
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
	chown "${SERVICE_USER}:${SERVICE_USER}" "${ETC_DIR}/config.yaml"
	chmod 0640 "${ETC_DIR}/config.yaml"
	echo
	echo "    Admin login: admin / ${ADMIN_PASSWORD}"
	echo "    (saved in ${ETC_DIR}/config.yaml — this is the only time it's printed)"
	echo
fi

echo "==> Installing systemd unit to ${UNIT_PATH}"
cat >"${UNIT_PATH}" <<EOF
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

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo "==> Installing log retention prune timer (runs 'coraza-waf-mod prune' every 15 days)"
cat >"${PRUNE_SERVICE_PATH}" <<EOF
[Unit]
Description=Coraza WAF Mod log retention prune (one-shot)

[Service]
Type=oneshot
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${VAR_DIR}
ExecStart=${INSTALL_PATH} prune ${ETC_DIR}/config.yaml
EOF

cat >"${PRUNE_TIMER_PATH}" <<EOF
[Unit]
Description=Run Coraza WAF Mod log retention prune every 15 days

[Timer]
OnBootSec=15min
OnUnitActiveSec=15d
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "==> Starting ${BINARY_NAME}"
systemctl daemon-reload
systemctl enable "${BINARY_NAME}"
systemctl restart "${BINARY_NAME}"
systemctl enable --now "${BINARY_NAME}-prune.timer"

echo
echo "Done. Check it with:"
echo "    sudo systemctl status ${BINARY_NAME}"
echo "    sudo journalctl -u ${BINARY_NAME} -f"
echo "    sudo systemctl list-timers ${BINARY_NAME}-prune.timer"
