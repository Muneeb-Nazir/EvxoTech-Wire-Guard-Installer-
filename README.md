# EvxoTech WireGuard Installer

**EvxoTech WireGuard Installer** — interactive installer for WireGuard server + minimal web dashboard (Flask). Designed to run inside an Ubuntu/Debian LXC or VM (Proxmox-friendly).

**Repo:** https://github.com/Muneeb-Nazir/EvxoTech-Wire-Guard-Installer-

---

## Contents
- `evxotech-wireguard-installer-v1.1-02112025.sh` — interactive installer
- `CHANGELOG.md`
- `latest_version.txt` — (optional) put `v1.1-02112025` here; used by script version-check

---

## Quick Start

1. Upload the script to the Debian/Ubuntu LXC/VM and run as root:
   ```bash
   chmod +x evxotech-wireguard-installer-v1.1-02112025.sh
   sudo ./evxotech-wireguard-installer-v1.1-02112025.sh

2. Follow prompts:
Public IP / Domain (for client Endpoint)
Server LAN IP (dashboard host)
WireGuard listen port (default 5555)
Number of client profiles to create
DNS to push to clients (use your AD DNS when ready)
Admin password for web dashboard (default Admin@123)

3. After install:
Client configs: /etc/wireguard/clients/
Client QR codes: /etc/wireguard/clients/qrcodes/
Dashboard (HTTP): http://<server_lan_ip>:10086 (Basic Auth)
username: admin
password: the password you entered during install (or Admin@123)

4. To create more clients later:
sudo /usr/local/bin/wg-add-client <client-name> [dns]
To uninstall (keeps backups):
sudo /usr/local/bin/evxotech-wg-uninstall
   
