Quick notes & next steps

Place this file on the Proxmox host (e.g. /root/evxotech-wireguard-lxc-precheck-v1.1-02112025.sh) and make it executable:

chmod +x /root/evxotech-wireguard-lxc-precheck-v1.1-02112025.sh


To run a read-only check:

sudo /root/evxotech-wireguard-lxc-precheck-v1.1-02112025.sh --check --ctid 107


To apply fixes interactively:

sudo /root/evxotech-wireguard-lxc-precheck-v1.1-02112025.sh --fix --ctid 107


To auto-apply fixes non-interactively:

sudo /root/evxotech-wireguard-lxc-precheck-v1.1-02112025.sh --fix --ctid 107 --yes

