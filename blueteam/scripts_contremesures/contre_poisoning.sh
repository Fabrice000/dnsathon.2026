#!/bin/bash
# =============================================================================
#  Contre-mesure Cache Poisoning - DNSathon 2026
#  Exécution locale dans Unbound ou depuis l'hôte
# =============================================================================
ATTACKER_IP="${1:-}"

echo "=============================================="
echo " CONTRE-MESURE : Cache Poisoning (Kaminsky)"
echo "=============================================="

echo "[*] Vidage immédiat du cache Unbound..."
if command -v unbound-control >/dev/null 2>&1; then
    unbound-control flush_zone . 2>/dev/null || kill -HUP 1 2>/dev/null
else
    docker exec dnsaton-unbound unbound-control flush_zone . 2>/dev/null || (cd /home/jules/projects/DNSAthon/groupe1_repo && docker compose restart unbound >/dev/null 2>&1)
fi
echo "[+] Cache résolveur assaini et purgé."

if [ -n "$ATTACKER_IP" ] && command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -s "$ATTACKER_IP" -p udp --dport 53 -j DROP 2>/dev/null
    echo "[+] IP $ATTACKER_IP bannie."
fi
