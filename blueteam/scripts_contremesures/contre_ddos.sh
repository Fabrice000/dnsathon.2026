#!/bin/bash
# =============================================================================
#  Contre-mesure DDoS / Water Torture - DNSathon 2026
#  Bloque les IP dépassant un seuil de requêtes DNS via iptables + hashlimit
# =============================================================================
# Usage : sudo bash contre_ddos.sh [IP_ATTAQUANT]
# =============================================================================

INTERFACE="${1:-any}"
ATTACKER_IP="$2"
LIMIT="30/sec"
BURST="20"

echo "=============================================="
echo " CONTRE-MESURE : DDoS / Water Torture"
echo "=============================================="

# Règle hashlimit globale : limite 10 req/s par IP, burst 20
echo "[*] Application de la règle iptables hashlimit..."
iptables -A INPUT -p udp --dport 53 \
    -m hashlimit \
    --hashlimit-name dns_flood \
    --hashlimit-above ${LIMIT} \
    --hashlimit-burst ${BURST} \
    --hashlimit-mode srcip \
    -j DROP

echo "[+] Règle hashlimit appliquée : DROP si > ${LIMIT} (burst ${BURST}) par IP sur port 53/udp"

# Si IP attaquant connue, blocage direct
if [ -n "$ATTACKER_IP" ]; then
    echo "[*] Blocage direct de l'IP attaquante : $ATTACKER_IP"
    iptables -I INPUT -s "$ATTACKER_IP" -p udp --dport 53 -j DROP
    echo "[+] IP $ATTACKER_IP bannie."
fi

echo ""
echo "[*] État actuel des règles iptables (port 53) :"
iptables -L INPUT -v -n --line-numbers | grep -E "53|DROP|ACCEPT|Chain"

echo ""
echo "[+] Contre-mesure DDoS déployée avec succès."
echo "    Pour supprimer : iptables -F INPUT"
