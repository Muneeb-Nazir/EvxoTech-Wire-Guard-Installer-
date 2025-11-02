#!/usr/bin/env bash
#
# evxotech-wireguard-lxc-precheck-v1.1-02112025.sh
# EvxoTech WireGuard LXC Precheck & Fix (v1.1-02112025)
# Run on Proxmox host (NOT inside LXC). Supports --check (default) and --fix.
#
# Usage:
#   # check interactively:
#   sudo ./evxotech-wireguard-lxc-precheck-v1.1-02112025.sh
#
#   # check specific container and don't prompt:
#   sudo ./evxotech-wireguard-lxc-precheck-v1.1-02112025.sh --ctid 107 --check --yes
#
#   # run fixes (interactive if --yes not provided):
#   sudo ./evxotech-wireguard-lxc-precheck-v1.1-02112025.sh --ctid 107 --fix
#
# Exit codes:
#   0 = OK (all checks passed)
#   1 = One or more checks failed (and not fixed)
#

set -euo pipefail

VERSION="v1.1-02112025"
LOGDIR="/var/log/evxotech-wireguard"
LOGFILE="${LOGDIR}/precheck.log"
TIMESTAMP() { date '+%F %T'; }

# Colors
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

mkdir -p "$LOGDIR"
touch "$LOGFILE"
exec 3>&1 1>>"${LOGFILE}" 2>&1

echo -e "${CYAN}EvxoTech WireGuard LXC Precheck & Fix — ${VERSION}${NC}"
echo -e "Log: ${LOGFILE}"
echo ""

# Helpers (print to both terminal and log)
log()   { printf "[%s]  %b\n" "$(TIMESTAMP)" "$*" | tee /dev/tty -a "${LOGFILE}"; }
ok()    { printf "[%s]  ${GREEN}✔ %b${NC}\n" "$(TIMESTAMP)" "$*" | tee -a "${LOGFILE}"; }
warn()  { printf "[%s]  ${YELLOW}! %b${NC}\n" "$(TIMESTAMP)" "$*" | tee -a "${LOGFILE}"; }
error() { printf "[%s]  ${RED}✖ %b${NC}\n" "$(TIMESTAMP)" "$*" | tee -a "${LOGFILE}"; }

usage() {
  cat <<EOF >&2
Usage: $0 [--check|--fix] [--ctid CTID] [--yes] [--help]

Options:
  --check        Run checks only (default)
  --fix          Apply fixes when checks fail
  --ctid <ID>    LXC container ID to patch (required for --fix or to verify inside container)
  --yes          Non-interactive: auto-apply fixes (implies --fix)
  --help         Show this help
EOF
  exit 1
}

# Defaults
MODE="check"
CTID=""
AUTO_YES=0

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --fix) MODE="fix"; shift ;;
    --ctid) CTID="$2"; shift 2 ;;
    --yes) AUTO_YES=1; MODE="fix"; shift ;;
    --help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

# Basic root check
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}ERROR:${NC} This script must be run as root on the Proxmox host." >&2
  exit 1
fi

log "Starting EvxoTech precheck (${VERSION}) (mode=${MODE})"

# FUNCTIONS
check_wireguard_module() {
  if lsmod | grep -q '^wireguard\b'; then
    ok "WireGuard kernel module: loaded"
    return 0
  else
    warn "WireGuard kernel module: NOT loaded"
    return 1
  fi
}

try_load_wireguard_module() {
  log "Attempting to modprobe wireguard..."
  if modprobe wireguard >/dev/null 2>&1; then
    ok "modprobe wireguard: success"
    return 0
  else
    warn "modprobe wireguard failed"
    return 1
  fi
}

install_wireguard_dkms() {
  log "Attempting to install wireguard-dkms and linux headers..."
  apt-get update -y >/dev/null 2>&1 || true
  # Install without halting if package problems occur
  apt-get install -y build-essential linux-headers-$(uname -r) wireguard-dkms wireguard-tools >/dev/null 2>&1 || {
    warn "apt-get install returned non-zero (see ${LOGFILE})"
    return 1
  }
  ok "Installed wireguard-dkms & linux-headers"
  depmod -a || true
  return 0
}

check_tun_device() {
  if [ -c /dev/net/tun ]; then
    ok "/dev/net/tun: exists"
    return 0
  else
    warn "/dev/net/tun: MISSING"
    return 1
  fi
}

create_tun_device() {
  log "Creating /dev/net/tun..."
  mkdir -p /dev/net
  if mknod /dev/net/tun c 10 200 >/dev/null 2>&1; then
    chmod 0666 /dev/net/tun || true
    ok "/dev/net/tun created"
    return 0
  else
    warn "Failed to create /dev/net/tun via mknod"
    return 1
  fi
}

check_lxc_conf_device_lines() {
  local conf="$1"
  if grep -q "lxc.cgroup2.devices.allow.*10:200" "$conf" >/dev/null 2>&1 && grep -q "lxc.mount.entry.*\/dev\/net\/tun" "$conf" >/dev/null 2>&1; then
    ok "LXC config ${conf}: has device permission and mount entry"
    return 0
  else
    warn "LXC config ${conf}: missing device permission or mount entry"
    return 1
  fi
}

patch_lxc_conf() {
  local conf="$1"
  log "Patching LXC config: ${conf}"
  # append lines if missing
  if ! grep -q "lxc.cgroup2.devices.allow.*10:200" "$conf" >/dev/null 2>&1; then
    echo "lxc.cgroup2.devices.allow = c 10:200 rwm" >> "$conf"
    ok "Added device allow line to ${conf}"
  else
    ok "Device allow line already present in ${conf}"
  fi
  if ! grep -q "lxc.mount.entry.*\/dev\/net\/tun" "$conf" >/dev/null 2>&1; then
    echo "lxc.mount.entry = /dev/net/tun dev/net/tun none bind,create=file" >> "$conf"
    ok "Added mount entry to ${conf}"
  else
    ok "Mount entry already present in ${conf}"
  fi
}

verify_tun_inside_container() {
  local id="$1"
  # Use pct exec to test existence
  if pct exec "$id" -- test -c /dev/net/tun >/dev/null 2>&1; then
    ok "Inside LXC ${id}: /dev/net/tun accessible"
    return 0
  else
    warn "Inside LXC ${id}: /dev/net/tun NOT accessible"
    return 1
  fi
}

# RUN CHECKS
RC=0

check_wireguard_module || RC=1
check_tun_device || RC=1

if [ -n "$CTID" ] && [ -f "/etc/pve/lxc/${CTID}.conf" ]; then
  CT_CONF="/etc/pve/lxc/${CTID}.conf"
  check_lxc_conf_device_lines "$CT_CONF" || RC=1
else
  if [ -n "$CTID" ]; then
    warn "LXC config /etc/pve/lxc/${CTID}.conf not found"
    RC=1
  else
    warn "No CTID provided: cannot verify LXC config or test inside container"
  fi
fi

if [ "$RC" -eq 0 ]; then
  ok "Precheck: All checks passed (wireguard module, /dev/net/tun, LXC config entries)."
  # If mode fix but everything is fine, nothing to do
  if [ "$MODE" = "fix" ]; then
    ok "Mode=fix but no fixes required."
  fi
  exit 0
fi

# At least one check failed
warn "Precheck: One or more checks failed."

if [ "$MODE" != "fix" ]; then
  echo ""
  echo -e "${YELLOW}Run with --fix to attempt automatic repairs (requires CTID if you want LXC patched).${NC}"
  exit 1
fi

# MODE == fix -> attempt fixes
log "Attempting automatic fixes..."

# 1) Try modprobe
if ! check_wireguard_module >/dev/null 2>&1; then
  if try_load_wireguard_module >/dev/null 2>&1; then
    ok "wireguard module loaded"
  else
    warn "Attempting to install dkms & headers and retry"
    if install_wireguard_dkms >/dev/null 2>&1; then
      if try_load_wireguard_module >/dev/null 2>&1; then
        ok "wireguard module loaded after dkms install"
      else
        error "Could not load wireguard module after dkms install"
        exit 1
      fi
    else
      error "Failed to install dkms or headers. See ${LOGFILE}"
      exit 1
    fi
  fi
fi

# 2) Ensure /dev/net/tun exists on host
if ! check_tun_device >/dev/null 2>&1; then
  if create_tun_device >/dev/null 2>&1; then
    ok "/dev/net/tun created on host"
  else
    error "Failed to create /dev/net/tun on host"
    exit 1
  fi
fi

# 3) Ensure LXC config patched if CTID provided
if [ -n "$CTID" ]; then
  CT_CONF="/etc/pve/lxc/${CTID}.conf"
  if [ ! -f "$CT_CONF" ]; then
    error "LXC config not found: ${CT_CONF}"
    exit 1
  fi
  # show planned changes and optionally ask
  if [ "$AUTO_YES" -eq 0 ]; then
    echo ""
    echo -e "${YELLOW}The script will modify ${CT_CONF} to allow /dev/net/tun access for the container.${NC}"
    read -rp "Proceed to patch ${CT_CONF}? (y/N): " RESP
    if [[ ! "$RESP" =~ ^[Yy]$ ]]; then
      warn "User declined to patch LXC config. Aborting."
      exit 1
    fi
  fi
  patch_lxc_conf "$CT_CONF"
  log "Restarting container ${CTID} to apply changes..."
  pct restart "$CTID" >/dev/null 2>&1 || {
    warn "pct restart returned non-zero; container might be running in different state. Trying pct start..."
    pct start "$CTID" >/dev/null 2>&1 || {
      error "Failed to restart/start container ${CTID}. Manual intervention required."
      exit 1
    }
  }
  sleep 4
  # Verify inside container
  if verify_tun_inside_container "$CTID"; then
    ok "Container ${CTID} now has /dev/net/tun accessible"
  else
    error "Container ${CTID} still cannot see /dev/net/tun after patch"
    exit 1
  fi
else
  warn "CTID not provided; LXC config not patched. If you want to patch a container pass --ctid <ID>."
  # We succeeded with host fixes but can't verify inside container
  ok "Host-level fixes applied. If container still fails, run this script with --ctid <ID> --fix."
  exit 0
fi

ok "All fixes applied successfully. Precheck complete."

exit 0
