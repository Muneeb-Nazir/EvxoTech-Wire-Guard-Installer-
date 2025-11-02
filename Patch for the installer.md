Replace the package installation section with the following:

# =========================
# Detect if running in LXC
# =========================
if [ -f /proc/1/environ ] && grep -q container=lxc /proc/1/environ; then
    IS_LXC=true
    log "Detected LXC container. Skipping kernel headers installation."
else
    IS_LXC=false
fi

# =========================
# Install Packages
# =========================
log "Installing required packages..."

# Common packages
apt update
apt install -y wireguard qrencode python3-venv dkms >/dev/null

# Only install headers if NOT in LXC
if [ "$IS_LXC" = false ]; then
    KERNEL_HEADERS="linux-headers-$(uname -r)"
    log "Installing $KERNEL_HEADERS..."
    apt install -y "$KERNEL_HEADERS"
else
    log "LXC detected — skipping kernel headers."
fi

# =========================
# Check if WireGuard module exists
# =========================
if ! modprobe wireguard &>/dev/null; then
    echo -e "${YELLOW}Warning: WireGuard kernel module not found.${NC}"
    echo -e "${YELLOW}Installer will attempt to use wireguard-go userspace implementation.${NC}"
    if ! command -v wireguard-go &>/dev/null; then
        log "Installing wireguard-go..."
        apt install -y golang-go
        go install golang.zx2c4.com/wireguard-go@latest
        export PATH=$PATH:$HOME/go/bin
    fi
fi
