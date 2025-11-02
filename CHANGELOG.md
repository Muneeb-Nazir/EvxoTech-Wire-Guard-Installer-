# Changelog

All notable changes to this project will be documented in this file.

## [v1.3-02112025] - 2025-11-02
### Added
- Auto-precheck integration: installer downloads and runs the LXC precheck before installing.
- Interactive precheck fix prompt (auto `--fix` with CTID).
- Full reinstall flow with DKMS/kernel module handling and manual fallback if `wg-quick` fails.
- Dashboard & admin password prompt.
- Logging directory: `/var/log/evxotech-wireguard/`

### Fixed
- Resolved `wg-quick` segmentation fault cases by ensuring kernel module availability and adding `ip` + `wg setconf` fallback.

## [v1.1-02112025] - 2025-11-02
### Added
- Initial installer with dashboard and client generator.

## [v1.0-02112025] - 2025-11-02
### Initial
- Basic installer & patch scripts.


## [v1.1-02112025] - 2025-11-02
### Added
- Interactive admin password prompt (default `Admin@123`) for the dashboard.
- Version check against GitHub `latest_version.txt`.
- Improved README and CHANGELOG for GitHub publishing.
- Optional self-signed HTTPS support for the Flask dashboard.
- Installer now supports automatic backup of existing `/etc/wireguard`.
- Flask dashboard environment variables set from systemd (admin user & password).
- Client generator helper `/usr/local/bin/wg-add-client`.

### Changed
- Default dashboard admin password changed from `Admin@` to `Admin@123`.
- Consolidated installer features into v1.1 (improved prompts, logging).

### Fixed
- Improved handling of missing dependencies and added `python3-venv` requirement.

## [v1.0-02112025] - 2025-11-02
### Initial release
- Basic installer / patch scripts
- Server configuration generation
- QR-code client generation
- Simple terminal helper for adding clients
- Systemd enablement for wg-quick

---

## Roadmap
- Windows PowerShell script to auto-install WireGuard and enable a persistent auto-connect service (for domain-joined Windows clients).
- Production-grade dashboard (RBAC, TLS via LetsEncrypt, CSRF protection).
- Non-destructive patch/merge mode to add peers without wiping configs.
