#!/bin/bash
# =============================================================================
#  Contre-mesure DNS Tunneling - DNSathon 2026
#  Exécution locale dans Unbound ou depuis l'hôte
# =============================================================================
TUNNEL_DOMAIN="${1:-tunnel.pirate.com}"
ATTACKER_IP="$2"

if [ -d "/opt/unbound/etc/unbound/blocklists" ]; then
    BLOCKLIST_DIR="/opt/unbound/etc/unbound/blocklists"
else
    BLOCKLIST_DIR="/home/jules/projects/DNSAthon/groupe1_repo/blocklists"
fi

echo "=============================================="
echo " CONTRE-MESURE : DNS Tunneling"
echo "=============================================="

BLOCKLIST_FILE="$BLOCKLIST_DIR/tunnel_block.conf"
echo "[*] Blocage du domaine de tunnel '$TUNNEL_DOMAIN'..."
mkdir -p "$BLOCKLIST_DIR"
cat > "$BLOCKLIST_FILE" << EOF
# Blocage anti-tunneling DNS - DNSathon 2026
local-zone: "${TUNNEL_DOMAIN}." always_nxdomain
EOF
echo "[+] Domaine '$TUNNEL_DOMAIN' bloqué dans Unbound."

if command -v iptables >/dev/null 2>&1; then
    iptables -A INPUT -p udp --dport 53 -m hashlimit --hashlimit-name dns_txt_lim --hashlimit-above 5/min --hashlimit-burst 10 --hashlimit-mode srcip -j DROP 2>/dev/null
fi

if [ -n "$ATTACKER_IP" ] && command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -s "$ATTACKER_IP" -p udp --dport 53 -j DROP 2>/dev/null
    echo "[+] IP $ATTACKER_IP bannie."
fi

if command -v unbound-control >/dev/null 2>&1; then
    unbound-control reload 2>/dev/null || kill -HUP 1 2>/dev/null
else
    cd /home/jules/projects/DNSAthon/groupe1_repo && docker compose restart unbound >/dev/null 2>&1
fi
echo "[+] Contre-mesure Tunneling appliquée."
