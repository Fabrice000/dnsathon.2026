#!/usr/bin/env python3
"""
=============================================================================
 Moteur de Détection Blue Team - DNSathon 2026 (Activité 3)
 Analyse le flux tcpdump en temps réel et détecte 4 types d'attaques DNS :
   1. DDoS / Water Torture (Random Subdomain Flood)
   2. Exfiltration de données (Entropie Shannon + longueur label)
   3. DNS Tunneling (requêtes TXT répétées / beaconing)
   4. Cache Poisoning (Kaminsky - rafale aléatoire sur même zone)
=============================================================================
 Usage :
   tcpdump -i any udp port 53 -n -l | python3 detect_engine.py
   python3 detect_engine.py <fichier_de_capture.txt>
=============================================================================
"""
import sys
import math
import time
import re
from collections import defaultdict, deque
from datetime import datetime

# ─────────────────────── Seuils de détection ───────────────────────
ENTROPY_THRESHOLD   = 3.6   # Entropie minimale pour alerter (exfiltration)
LABEL_LEN_THRESHOLD = 25    # Longueur label suspecte (exfiltration)
DDOS_RATE_THRESHOLD = 30    # req/s par IP sur fenêtre glissante 2s (DDoS)
TUNNEL_TXT_THRESHOLD = 3    # Nombre de requêtes TXT depuis la même IP pour alerter
POISON_RATE_THRESHOLD = 5   # req/s aléatoires sur même zone parent (Poisoning)
WINDOW_SEC = 2.0            # Fenêtre glissante en secondes

# ─────────────────────── Couleurs ANSI ─────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
PURPLE = "\033[95m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────── Fonctions utilitaires ──────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def clean_window(dq: deque, now: float, window: float = WINDOW_SEC):
    while dq and dq[0] < now - window:
        dq.popleft()

# ─────────────────────── Parseurs de format ─────────────────────────
def parse_tcpdump(line: str):
    """
    Extrait (src_ip, fqdn, qtype) depuis une ligne tcpdump.
    Exemples supportés :
      12:01:05.123 IP 172.28.0.1.49312 > 172.28.0.2.53: 12345+ A? random.banque.bj. (29)
      12:01:05.123 IP 10.0.0.5.1234 > 10.0.0.2.53: 999+ TXT? hex.c2.tunnel.com. (40)
    """
    # Format tcpdump standard
    m = re.search(
        r'(\d+\.\d+\.\d+\.\d+)\.\d+\s*>\s*[\d\.]+\.53:.*?([A-Z]+)\?\s*([\w\.\-]+)',
        line
    )
    if m:
        return m.group(1), m.group(3).rstrip('.'), m.group(2)

    # Format alternatif avec port collé
    m2 = re.search(
        r'(\d+\.\d+\.\d+\.\d+)\s+>\s+[\d\.]+:\s+.*?([A-Z]+)\?\s*([\w\.\-]+)',
        line
    )
    if m2:
        return m2.group(1), m2.group(3).rstrip('.'), m2.group(2)

    return None, None, None

def parse_unbound_log(line: str):
    """
    Extrait (src_ip, fqdn, qtype) depuis un log Unbound (log-queries: yes).
    Exemple : [1716800465] unbound[1:0] info: 172.28.0.1 google.com. A IN
    """
    m = re.search(
        r'info:\s+(\d+\.\d+\.\d+\.\d+)\s+([\w\.\-]+)\.\s+([A-Z]+)\s+IN',
        line
    )
    if m:
        return m.group(1), m.group(2), m.group(3)
    return None, None, None

def parse_line(line: str):
    """Auto-détection du format (tcpdump vs log Unbound)."""
    ip, fqdn, qtype = parse_tcpdump(line)
    if ip:
        return ip, fqdn, qtype
    ip, fqdn, qtype = parse_unbound_log(line)
    if ip:
        return ip, fqdn, qtype
    return None, None, None

# ─────────────────────── Moteur d'analyse ───────────────────────────
def analyze(ip: str, fqdn: str, qtype: str, state: dict):
    now = time.time()
    now_ts = ts()
    labels = fqdn.split('.')
    subdomain = labels[0] if labels else ""
    zone_parent = '.'.join(labels[1:]) if len(labels) > 1 else fqdn

    # ── 1. Suivi volumétrique global par IP ──────────────────────────
    clean_window(state['ip_times'][ip], now)
    state['ip_times'][ip].append(now)
    rate = len(state['ip_times'][ip]) / WINDOW_SEC

    # ── 2. Détection DDoS / Water Torture ────────────────────────────
    if rate > DDOS_RATE_THRESHOLD:
        if not state['alerted_ddos'].get(ip):
            print(f"{RED}{BOLD}[ALERT DDoS]{RESET} {now_ts} | "
                  f"IP: {ip} | Débit: {rate:.1f} req/s (seuil={DDOS_RATE_THRESHOLD}) | "
                  f"Cible: {fqdn}")
            state['alerted_ddos'][ip] = now
        elif now - state['alerted_ddos'][ip] > 5:
            # Re-alerter toutes les 5 secondes
            print(f"{RED}[ALERT DDoS - EN COURS]{RESET} {now_ts} | "
                  f"IP: {ip} | {rate:.1f} req/s")
            state['alerted_ddos'][ip] = now

    # ── 3. Détection Exfiltration (Entropie + Longueur) ──────────────
    if len(subdomain) >= LABEL_LEN_THRESHOLD:
        entropy = shannon_entropy(subdomain)
        if entropy >= ENTROPY_THRESHOLD:
            print(f"{PURPLE}{BOLD}[ALERT EXFILTRATION]{RESET} {now_ts} | "
                  f"IP: {ip} | Label: '{subdomain}' | "
                  f"Longueur: {len(subdomain)} | Entropie: {entropy:.2f} | "
                  f"FQDN: {fqdn}")

    # ── 4. Détection DNS Tunneling (requêtes TXT répétées) ───────────
    if qtype in ('TXT', 'NULL'):
        state['txt_counts'][ip] += 1
        count = state['txt_counts'][ip]
        if count >= TUNNEL_TXT_THRESHOLD and count % TUNNEL_TXT_THRESHOLD == 0:
            print(f"{YELLOW}{BOLD}[ALERT TUNNELING]{RESET} {now_ts} | "
                  f"IP: {ip} | Type: {qtype} | FQDN: {fqdn} | "
                  f"({count} requêtes TXT/NULL depuis cette IP)")

    # ── 5. Détection Cache Poisoning (Kaminsky) ───────────────────────
    # Signature : rafale de sous-domaines aléatoires vers la MÊME zone parent
    if len(labels) >= 3 and len(subdomain) >= 8:
        entropy = shannon_entropy(subdomain)
        if entropy >= 3.0:
            clean_window(state['zone_times'][zone_parent], now)
            state['zone_times'][zone_parent].append(now)
            zone_rate = len(state['zone_times'][zone_parent]) / WINDOW_SEC
            if zone_rate > POISON_RATE_THRESHOLD:
                if not state['alerted_poison'].get(zone_parent):
                    print(f"{CYAN}{BOLD}[ALERT CACHE POISONING]{RESET} {now_ts} | "
                          f"IP: {ip} | Zone ciblée: {zone_parent} | "
                          f"Sous-domaines aléatoires: {zone_rate:.1f}/s | "
                          f"Tentative Kaminsky détectée !")
                    state['alerted_poison'][zone_parent] = now
                elif now - state['alerted_poison'][zone_parent] > 5:
                    print(f"{CYAN}[ALERT POISONING - EN COURS]{RESET} {now_ts} | "
                          f"Zone: {zone_parent} | {zone_rate:.1f} rafales/s")
                    state['alerted_poison'][zone_parent] = now

def new_state() -> dict:
    return {
        'ip_times':      defaultdict(deque),
        'zone_times':    defaultdict(deque),
        'txt_counts':    defaultdict(int),
        'alerted_ddos':  {},
        'alerted_poison':{},
    }

def monitor_stream(stream):
    banner = f"""
{GREEN}{BOLD}╔══════════════════════════════════════════════════════╗
║   Blue Team IDS - DNSathon 2026 - Activité 3         ║
║   Détection temps réel : DDoS | Exfil | Tunnel | Poison ║
╚══════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)
    print(f"{GREEN}[*] Sonde active. En attente de trafic DNS...{RESET}\n")
    state = new_state()
    for raw_line in stream:
        line = raw_line.strip()
        if not line:
            continue
        ip, fqdn, qtype = parse_line(line)
        if ip and fqdn and qtype:
            analyze(ip, fqdn, qtype, state)

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            with open(sys.argv[1], 'r') as f:
                monitor_stream(f)
        else:
            monitor_stream(sys.stdin)
    except KeyboardInterrupt:
        print(f"\n{GREEN}[*] Détection arrêtée.{RESET}")
