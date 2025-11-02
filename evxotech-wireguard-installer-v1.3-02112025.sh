#!/usr/bin/env bash
#
# evxotech-wireguard-installer-v1.3-02112025.sh
# EvxoTech WireGuard Installer v1.3 (Full Reinstall; Precheck-integrated)
# Version: v1.3-02112025
# GitHub repo: https://github.com/Muneeb-Nazir/EvxoTech-Wire-Guard-Installer-
#
# Behavior:
# - Auto-downloads precheck script from GitHub if missing
# - Runs precheck (--check). If problems found asks to run (--fix)
# - If user accepts, runs precheck --fix --ctid <CTID> (requires host access)
# - After precheck passes, performs the full reinstall of WireGuard and dashboard
#
set -euo pipefail

VERSION="v1.3-02112025"
LOGDIR="/var/log/evxotech-wireguard"
LOGFILE="${LOGDIR}/install.log"
PRECHECK_FILENAME="evxotech-wireguard-lxc-precheck-v1.1-02112025.sh"
PRECHECK_URL_RAW="https://raw.githubusercontent.com/Muneeb-Nazir/EvxoTech-Wire-Guard-Installer-/main/${PRECHECK_FILENAME}"
INSTALLER_PATH="/root/${PRECHECK_FILENAME}"
WG_IF="wg0"
SERVER_CONF="/etc/wireguard/${WG_IF}.conf"
CLIENT_DIR="/root/wireguard-clients"
DASHBOARD_DIR="/opt/evxotech/wg-dashboard"
DASHBOARD_PORT_HTTP="10086"
DASHBOARD_PORT_HTTPS="10443"
ADMIN_USER="admin"
ADMIN_PASS_DEFAULT="Admin@123"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

mkdir -p "$LOGDIR"
touch "$LOGFILE"

log() { echo -e "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"; }
info() { echo -e "${BLUE}$*${NC}" | tee -a "$LOGFILE"; }
success() { echo -e "${GREEN}$*${NC}" | tee -a "$LOGFILE"; }
warn() { echo -e "${YELLOW}$*${NC}" | tee -a "$LOGFILE"; }
fatal() { echo -e "${RED}$*${NC}" | tee -a "$LOGFILE"; exit 1; }

require_root(){ if [ "$(id -u)" -ne 0 ]; then fatal "Run as root."; fi }

banner(){
  cat <<'EOF'
   _____  _   _ _   _  __      __         _    
  | ____|| \ | | \ | | \ \    / /   ___  | | __
  |  _|  |  \| |  \| |  \ \  / /   / _ \ | |/ /
  | |___ | |\  | |\  |   \ \/ /   |  __/ |   < 
  |_____||_| \_|_| \_|    \__/     \___| |_|\_\
                                               
    EvxoTech WireGuard Installer — version: '"$VERSION"'
EOF
}

version_check() {
  local latest=""
  latest=$(curl -fsS --max-time 5 "https://raw.githubusercontent.com/Muneeb-Nazir/EvxoTech-Wire-Guard-Installer-/main/latest_version.txt" 2>/dev/null || true)
  if [ -n "$latest" ] && [ "$latest" != "$VERSION" ]; then
    warn "Update available: ${latest} (you have ${VERSION}). Repo: https://github.com/Muneeb-Nazir/EvxoTech-Wire-Guard-Installer-"
  else
    success "Version check: installer ${VERSION}"
  fi
}

download_precheck() {
  if [ ! -f "$INSTALLER_PATH" ]; then
    info "Downloading precheck script from GitHub..."
    if ! curl -fsSLo "$INSTALLER_PATH" "$PRECHECK_URL_RAW"; then
      warn "Could not download precheck script from ${PRECHECK_URL_RAW}. You can place it at ${INSTALLER_PATH} manually."
      return 1
    fi
    chmod +x "$INSTALLER_PATH"
    success "Precheck script downloaded to ${INSTALLER_PATH}"
  else
    info "Precheck script already exists at ${INSTALLER_PATH}"
  fi
  return 0
}

run_precheck_check() {
  if [ ! -x "$INSTALLER_PATH" ]; then
    fatal "Precheck script missing or not executable: ${INSTALLER_PATH}"
  fi
  info "Running precheck in check-only mode..."
  if bash "$INSTALLER_PATH" --check --ctid "${CTID:-}" ; then
    success "Precheck: OK"
    return 0
  else
    warn "Precheck: issues detected"
    return 1
  fi
}

run_precheck_fix() {
  info "Running precheck with fixes (non-interactive: --yes)..."
  if bash "$INSTALLER_PATH" --fix --ctid "${CTID:-}" --yes ; then
    success "Precheck fixes applied"
    return 0
  else
    fatal "Precheck automatic fix failed. Please inspect ${INSTALLER_PATH} logs."
  fi
}

# --- Installer prompts ---
prompt_user() {
  PUB_DETECT=$(curl -s https://ifconfig.co || curl -s https://ipinfo.io/ip || true)
  LOCAL_DETECT=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}')
  LOCAL_DETECT=${LOCAL_DETECT:-$(hostname -I 2>/dev/null | awk '{print $1}')}
  LOCAL_DETECT=${LOCAL_DETECT:-"10.120.80.140"}

  echo ""
  read -rp "Enter CTID of the LXC you'll install WireGuard in (Proxmox CTID) [leave blank if installing inside container already]: " CTID
  read -rp "Public IP or Domain for clients to connect [${PUB_DETECT}]: " PUBLIC_IP
  PUBLIC_IP=${PUBLIC_IP:-$PUB_DETECT}
  read -rp "Server LAN IP (dashboard host) [detected: ${LOCAL_DETECT}]: " SERVER_LAN_IP
  SERVER_LAN_IP=${SERVER_LAN_IP:-$LOCAL_DETECT}
  read -rp "WireGuard listening port [5555]: " WG_PORT
  WG_PORT=${WG_PORT:-5555}
  read -rp "WireGuard internal CIDR [10.120.80.0/24]: " LAN_CIDR
  LAN_CIDR=${LAN_CIDR:-10.120.80.0/24}
  read -rp "How many client configs to create initially [1]: " CLIENT_COUNT
  CLIENT_COUNT=${CLIENT_COUNT:-1}
  read -rp "DNS to push to clients [10.120.80.10]: " DNS_PLACEHOLDER
  DNS_PLACEHOLDER=${DNS_PLACEHOLDER:-10.120.80.10}
  echo -e "Enter admin password for dashboard (press Enter for default: ${ADMIN_PASS_DEFAULT}):"
  read -srp "Admin password: " ADMIN_PASS; echo ""
  ADMIN_PASS=${ADMIN_PASS:-$ADMIN_PASS_DEFAULT}

  echo ""
  echo "Summary:"
  echo " CTID (optional): ${CTID}"
  echo " Public endpoint: ${PUBLIC_IP}"
  echo " Server LAN IP: ${SERVER_LAN_IP}"
  echo " WG Port: ${WG_PORT}"
  echo " LAN CIDR: ${LAN_CIDR}"
  echo " Clients to create: ${CLIENT_COUNT}"
  echo " DNS placeholder: ${DNS_PLACEHOLDER}"
  echo " Dashboard admin: ${ADMIN_USER} / (password hidden)"
  read -rp "Proceed? (y/N): " CONF
  if [[ ! "$CONF" =~ ^[Yy]$ ]]; then
    fatal "Aborted by user."
  fi
}

install_packages() {
  log "Installing packages..."
  apt-get update -y >>"$LOGFILE" 2>&1
  apt-get install -y build-essential linux-headers-$(uname -r) wireguard wireguard-dkms wireguard-tools qrencode python3-venv python3-pip iproute2 iptables curl wget git >/dev/null 2>&1 || {
    fatal "Failed to install packages. Check $LOGFILE"
  }
  success "Packages installed."
}

backup_existing() {
  if [ -d /etc/wireguard ] && [ "$(ls -A /etc/wireguard 2>/dev/null)" ]; then
    TS=$(date '+%Y%m%d-%H%M%S')
    BACKUP_DIR="/etc/wireguard-backup-${TS}"
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/wireguard/* "$BACKUP_DIR/" 2>/dev/null || true
    log "Backed up /etc/wireguard -> ${BACKUP_DIR}"
  fi
}

ensure_tun_and_module() {
  log "Ensuring /dev/net/tun and wireguard module available..."
  if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 || true
    chmod 0666 /dev/net/tun || true
  fi
  if ! modprobe wireguard >/dev/null 2>&1; then
    log "modprobe wireguard failed; attempting to install dkms..."
    apt-get install -y wireguard-dkms linux-headers-$(uname -r) >>"$LOGFILE" 2>&1 || true
    depmod -a || true
    if ! modprobe wireguard >/dev/null 2>&1; then
      warn "WireGuard kernel module not loadable. If using Proxmox LXC, run precheck on host and ensure host has module loaded."
    fi
  fi
}

generate_server_keys_and_conf() {
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard
  umask 077
  wg genkey | tee /etc/wireguard/server_private.key >/dev/null
  wg pubkey < /etc/wireguard/server_private.key > /etc/wireguard/server_public.key
  SERVER_PRIV_KEY=$(cat /etc/wireguard/server_private.key)
  SERVER_PUB_KEY=$(cat /etc/wireguard/server_public.key)

  BASE_PREFIX=$(echo "$LAN_CIDR" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
  WG_SERVER_IP="${BASE_PREFIX}.1"

  cat > "$SERVER_CONF" <<EOF
[Interface]
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
SaveConfig = true
PostUp = /usr/sbin/ip -4 rule add from ${WG_SERVER_IP}/32 table evx || true; /usr/sbin/ip -4 route add ${LAN_CIDR} dev ${WG_IF} || true; /usr/sbin/iptables -A FORWARD -i ${WG_IF} -o eth0 -j ACCEPT || true; /usr/sbin/iptables -A FORWARD -i eth0 -o ${WG_IF} -j ACCEPT || true
PostDown = /usr/sbin/ip -4 rule del from ${WG_SERVER_IP}/32 table evx || true; /usr/sbin/ip -4 route del ${LAN_CIDR} dev ${WG_IF} || true; /usr/sbin/iptables -D FORWARD -i ${WG_IF} -o eth0 -j ACCEPT || true; /usr/sbin/iptables -D FORWARD -i eth0 -o ${WG_IF} -j ACCEPT || true
# Server public key:
# ${SERVER_PUB_KEY}
EOF
  chmod 600 "$SERVER_CONF"
  success "Server config written to ${SERVER_CONF} (WG IP: ${WG_SERVER_IP})"
}

install_wg_add_client() {
  mkdir -p "$CLIENT_DIR/qrcodes"
  cat > /usr/local/bin/wg-add-client <<'WGADD'
#!/usr/bin/env bash
# wg-add-client <name> [dns]
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
CLIENT_DIR="/root/wireguard-clients"
WG_IF="wg0"
PUBLIC_IP="__PUBLIC_IP__"
WG_PORT="__WG_PORT__"
LAN_CIDR="__LAN_CIDR__"
DEFAULT_DNS="__DNS__"
if [ -z "$1" ]; then echo "Usage: wg-add-client <client-name> [dns]"; exit 1; fi
CLIENT_NAME="$1"
DNS="${2:-$DEFAULT_DNS}"
mkdir -p "$CLIENT_DIR"
umask 077
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
USED=$(grep -h "^Address" $CLIENT_DIR/*.conf 2>/dev/null | awk '{print $3}' | cut -d'/' -f1 || true)
BASE=$(echo "$LAN_CIDR" | cut -d'.' -f1-3)
IP=""
for i in $(seq 2 250); do
  CAND="${BASE}.${i}"
  if ! echo "$USED" | grep -q "^${CAND}$"; then IP="$CAND"; break; fi
done
if [ -z "$IP" ]; then echo "No free IP"; exit 1; fi
SERVER_PUB=$(wg show $WG_IF public-key 2>/dev/null || cat /etc/wireguard/server_public.key 2>/dev/null)
cat > "${CLIENT_DIR}/${CLIENT_NAME}.conf" <<EOC
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${IP}/24
DNS = ${DNS}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${PUBLIC_IP}:${WG_PORT}
AllowedIPs = ${LAN_CIDR}
PersistentKeepalive = 25
EOC
chmod 600 "${CLIENT_DIR}/${CLIENT_NAME}.conf"
wg set $WG_IF peer ${CLIENT_PUB} allowed-ips ${IP}/32 >/dev/null 2>&1 || true
if command -v qrencode >/dev/null 2>&1; then qrencode -o "${CLIENT_DIR}/qrcodes/${CLIENT_NAME}.png" -r "${CLIENT_DIR}/${CLIENT_NAME}.conf"; fi
echo "Created ${CLIENT_DIR}/${CLIENT_NAME}.conf (IP ${IP}). QR: ${CLIENT_DIR}/qrcodes/${CLIENT_NAME}.png"
WGADD

  sed -e "s|__PUBLIC_IP__|${PUBLIC_IP}|g" \
      -e "s|__WG_PORT__|${WG_PORT}|g" \
      -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
      -e "s|__DNS__|${DNS_PLACEHOLDER}|g" \
      /usr/local/bin/wg-add-client > /usr/local/bin/wg-add-client.tmp && mv /usr/local/bin/wg-add-client.tmp /usr/local/bin/wg-add-client
  chmod +x /usr/local/bin/wg-add-client
  success "Installed wg-add-client helper"
}

bring_up_wg_with_fallback() {
  if wg-quick up "$WG_IF" >/dev/null 2>&1; then
    success "wg-quick up succeeded"
    return 0
  fi
  warn "wg-quick failed; attempting manual bring-up fallback..."
  ip link delete dev "$WG_IF" >/dev/null 2>&1 || true
  ip link add dev "$WG_IF" type wireguard >/dev/null 2>&1 || { fatal "Manual add failed; kernel module missing?"; }
  ip address add "${WG_SERVER_IP}/24" dev "$WG_IF" >/dev/null 2>&1 || true
  if wg setconf "$WG_IF" "$SERVER_CONF" >/dev/null 2>&1; then
    ip link set up dev "$WG_IF" >/dev/null 2>&1 || true
    success "Manual bring-up (ip + wg setconf) succeeded"
    return 0
  else
    fatal "Manual wg setconf failed"
  fi
}

setup_dashboard() {
  success "Installing minimal Flask dashboard at ${DASHBOARD_DIR}..."
  mkdir -p "${DASHBOARD_DIR}"
  cat > "${DASHBOARD_DIR}/app.py" <<'PY'
from flask import Flask, render_template_string, request, redirect, url_for, send_from_directory, abort
import os, subprocess, hmac
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = "/root/wireguard-clients"
ADMIN_USER = os.environ.get("WG_ADMIN_USER","admin")
ADMIN_PASS = os.environ.get("WG_ADMIN_PASS","Admin@123")
app = Flask(__name__)
def check_auth(u, p):
    return hmac.compare_digest(u, ADMIN_USER) and hmac.compare_digest(p, ADMIN_PASS)
def auth_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return ('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return func(*args, **kwargs)
    return wrapper
INDEX_TMPL = """
<!doctype html><title>EvxoTech WG Dashboard</title>
<h2>EvxoTech WireGuard Dashboard</h2>
<p>Admin: {{admin}}</p>
<form method="post" action="{{url_for('add_client')}}">
  <label>Client name: <input name="name"></label>
  <label>DNS (optional): <input name="dns" placeholder="10.120.80.10"></label>
  <button type="submit">Create Client</button>
</form>
<h3>Existing Clients</h3>
<ul>
{% for c in clients %}
  <li>{{c}} - <a href="{{url_for('download_conf',name=c)}}">Download</a> - <a href="{{url_for('download_qr',name=c)}}">QR</a></li>
{% endfor %}
</ul>
"""
@app.route('/')
@auth_required
def index():
    clients = []
    if os.path.isdir(CLIENT_DIR):
        clients = [f[:-5] for f in os.listdir(CLIENT_DIR) if f.endswith('.conf')]
    return render_template_string(INDEX_TMPL, clients=clients, admin=os.environ.get("WG_ADMIN_USER","admin"))
@app.route('/add', methods=['POST'])
@auth_required
def add_client():
    name = request.form.get('name','').strip()
    dns = request.form.get('dns','').strip()
    if not name:
        return "Client name required", 400
    cmd = ["/usr/local/bin/wg-add-client", name]
    if dns:
        cmd.append(dns)
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return f"Error creating client: {e.output}", 500
    return redirect(url_for('index'))
@app.route('/conf/<name>')
@auth_required
def download_conf(name):
    path = os.path.join(CLIENT_DIR, f"{name}.conf")
    if not os.path.isfile(path):
        abort(404)
    return send_from_directory(CLIENT_DIR, f"{name}.conf", as_attachment=True)
@app.route('/qr/<name>')
@auth_required
def download_qr(name):
    png = os.path.join(CLIENT_DIR, "qrcodes", f"{name}.png")
    if os.path.isfile(png):
        return send_from_directory(os.path.join(CLIENT_DIR,"qrcodes"), f"{name}.png", as_attachment=True)
    else:
        return "QR not found", 404
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=${DASHBOARD_PORT_HTTP})
PY

  cat > "${DASHBOARD_DIR}/requirements.txt" <<'REQ'
Flask==2.3.2
REQ

  python3 -m venv "${DASHBOARD_DIR}/venv" >/dev/null 2>&1
  "${DASHBOARD_DIR}/venv/bin/pip" install --upgrade pip >/dev/null 2>&1
  "${DASHBOARD_DIR}/venv/bin/pip" install -r "${DASHBOARD_DIR}/requirements.txt" >/dev/null 2>&1

  cat > /etc/systemd/system/evxotech-wg-dashboard.service <<SERVICE
[Unit]
Description=EvxoTech WireGuard Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=${DASHBOARD_DIR}
Environment="WG_ADMIN_USER=${ADMIN_USER}"
Environment="WG_ADMIN_PASS=${ADMIN_PASS}"
ExecStart=${DASHBOARD_DIR}/venv/bin/python ${DASHBOARD_DIR}/app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable evxotech-wg-dashboard.service >/dev/null 2>&1
  systemctl start evxotech-wg-dashboard.service >/dev/null 2>&1 || warn "Dashboard service start failed; check systemctl status."
  success "Dashboard installed (HTTP ${DASHBOARD_PORT_HTTP})."
}

create_uninstaller() {
  cat > /usr/local/bin/evxotech-wg-uninstall <<'UNINST'
#!/usr/bin/env bash
echo "EvxoTech WireGuard Uninstall"
read -p "Type YES to confirm uninstall: " CONF
if [ "$CONF" != "YES" ]; then echo "Aborted."; exit 0; fi
systemctl stop evxotech-wg-dashboard.service 2>/dev/null || true
systemctl disable evxotech-wg-dashboard.service 2>/dev/null || true
rm -rf /opt/evxotech/wg-dashboard 2>/dev/null || true
systemctl stop wg-quick@wg0.service 2>/dev/null || true
systemctl disable wg-quick@wg0.service 2>/dev/null || true
rm -rf /etc/wireguard 2>/dev/null || true
rm -rf /root/wireguard-clients 2>/dev/null || true
rm -f /usr/local/bin/wg-add-client /usr/local/bin/evxotech-wg-uninstall 2>/dev/null || true
echo "Uninstall complete. Backups (if any) at /etc/wireguard-backup-*"
UNINST
  chmod +x /usr/local/bin/evxotech-wg-uninstall
  success "Uninstaller created at /usr/local/bin/evxotech-wg-uninstall"
}

main() {
  require_root
  banner
  version_check
  download_precheck || warn "Precheck download failed; ensure ${PRECHECK_FILENAME} exists in repo root."

  # Run precheck
  read -rp "Run precheck now? (Y/n): " RUN_PRECHECK
  RUN_PRECHECK=${RUN_PRECHECK:-Y}
  if [[ "$RUN_PRECHECK" =~ ^[Yy]$ ]]; then
    if run_precheck_check; then
      success "Precheck OK — proceeding."
    else
      echo ""
      read -rp "Precheck found issues. Attempt automatic fixes? (y/N): " WANT_FIX
      if [[ "$WANT_FIX" =~ ^[Yy]$ ]]; then
        read -rp "Enter CTID of LXC to patch (required for fix): " CTID
        if [ -z "${CTID}" ]; then fatal "CTID required for automatic fix."; fi
        run_precheck_fix
      else
        fatal "Cannot proceed until precheck issues are resolved."
      fi
    fi
  fi

  # Prompts for installer
  prompt_user

  install_packages
  ensure_tun_and_module
  backup_existing
  generate_server_keys_and_conf
  install_wg_add_client

  # attempt bring up
  bring_up_wg_with_fallback

  # create initial clients
  for i in $(seq 1 "$CLIENT_COUNT"); do
    /usr/local/bin/wg-add-client "client${i}" "$DNS_PLACEHOLDER" >/dev/null 2>&1 || true
  done

  setup_dashboard
  create_uninstaller

  success "EvxoTech WireGuard installation complete!"
  echo "Dashboard URL: http://${SERVER_LAN_IP}:${DASHBOARD_PORT_HTTP}"
  echo "Admin user: ${ADMIN_USER}  (password you set)"
  echo "Client configs & QR: ${CLIENT_DIR}"
  exit 0
}

main "$@"
