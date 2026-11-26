#!/bin/bash
# =============================================================================
#  Contre-mesure Exfiltration DNS - DNSathon 2026
#  Exécution locale dans Unbound ou depuis l'hôte
# =============================================================================
EXFIL_DOMAIN="${1:-malicious-exfil.com}"
ATTACKER_IP="$2"

# Détection de l'environnement (dans le conteneur ou sur l'hôte)
if [ -d "/opt/unbound/etc/unbound/blocklists" ]; then
    BLOCKLIST_DIR="/opt/unbound/etc/unbound/blocklists"
else
    BLOCKLIST_DIR="/home/jules/projects/DNSAthon/groupe1_repo/blocklists"
fi

echo "=============================================="
echo " CONTRE-MESURE : Exfiltration DNS"
echo "=============================================="

BLOCKLIST_FILE="$BLOCKLIST_DIR/exfil_block.conf"
echo "[*] Ajout du domaine '$EXFIL_DOMAIN' à la blocklist Unbound..."
mkdir -p "$BLOCKLIST_DIR"
cat > "$BLOCKLIST_FILE" << EOF
# Blocage anti-exfiltration DNS - DNSathon 2026
local-zone: "${EXFIL_DOMAIN}." always_nxdomain
EOF
echo "[+] Domaine '$EXFIL_DOMAIN' bloqué dans Unbound (réponse NXDOMAIN forcée)."

# Recharger Unbound
if command -v unbound-control >/dev/null 2>&1; then
    unbound-control reload 2>/dev/null || kill -HUP 1 2>/dev/null
else
    cd /home/jules/projects/DNSAthon/groupe1_repo && docker compose restart unbound >/dev/null 2>&1
fi
echo "[+] Configuration Unbound rechargée."

if [ -n "$ATTACKER_IP" ]; then
    iptables -I INPUT -s "$ATTACKER_IP" -p udp --dport 53 -j DROP 2>/dev/null
    echo "[+] IP $ATTACKER_IP bannie."
fi
