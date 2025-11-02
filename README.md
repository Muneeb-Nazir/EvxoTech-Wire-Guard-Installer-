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
   
Notes & Caveats

The installer uses eth0 in the PostUp/PostDown iptables commands. Edit /etc/wireguard/wg0.conf if your container uses a different interface (e.g., ens18).

By default the dashboard runs on HTTP (port 10086). The script can optionally create a self-signed certificate and start an HTTPS service on 10443.

The dashboard is a lightweight admin tool for adding clients and downloading configs. It uses HTTP Basic Auth (credentials are stored as environment variables in systemd service). For production, use stronger secret management and TLS from a trusted CA.

If machines must authenticate to a Domain Controller before a user logs in (Windows "connect before logon"), WireGuard alone may not satisfy that. A Windows auto-connect service script can be used to make the tunnel available at boot — see scripts/ (planned).

The script performs a simple version check by reading latest_version.txt from the repository. Upload that file to the repo root to enable version detection.

Security Recommendations

Replace default admin password immediately (the installer prompts for one).

If exposing the dashboard publicly, secure with proper TLS (Let’s Encrypt) and restrict access via firewall.

Store and manage client config files securely — they grant network access.

Troubleshooting

wg-quick up wg0 fails:

Check /var/log/evxotech-wireguard-install.log

Inspect /etc/wireguard/wg0.conf for interface name mismatches and correct PostUp/PostDown

Firewall / NAT:

If the LXC container has no native route to LAN, uncomment the MASQUERADE lines in /etc/wireguard/wg0.conf and adjust the external interface name.
