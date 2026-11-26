# Manuel Pédagogique et Guide de Déploiement : DNSaton
### Conception, Sécurisation et Exploitation d'un Résolveur DNS Public Moderne
> **Document de formation technique à l'attention des cadets et de l'équipe projet**  
> **Auteur / Lead :** Équipe DNSaton — Hackathon 2026  
> **Niveau :** Administrateur Réseau & Analyste Cybersécurité Junior

---

## 1. Objectifs Pédagogiques du Projet

À l'issue de cette session et de la mise en œuvre de ce projet, chaque cadet doit être capable de :
1. **Comprendre la hiérarchie DNS mondiale** (Racines, TLDs, Autoritaires, Récursifs).
2. **Identifier les vulnérabilités fondamentales** du protocole DNS historique (écoute passive, empoisonnement de cache Kaminsky, amplification DDoS).
3. **Mettre en œuvre les mécanismes de chiffrement modernes** : DoT (*DNS over TLS*) et DoH (*DNS over HTTPS*).
4. **Valider cryptographiquement l'intégrité des zones** via DNSSEC (drapeau `ad` et rejet `SERVFAIL`).
5. **Déployer une architecture de défense en profondeur (*Two-Tier*)** associant un frontal de sécurité (DNSdist) et un moteur de résolution récursif isolé (Unbound).
6. **Superviser l'infrastructure en temps réel** à l'aide de métriques Prometheus et de tableaux de bord Grafana.

---

## 2. Références Officielles et RFC Incontournables

Pour appuyer votre démarche technique avec rigueur académique et professionnelle, voici les normes et documentations de référence :

### Les Standards de l'IETF (RFC - Request For Comments)
* [RFC 1035 (1987)](https://datatracker.ietf.org/doc/html/rfc1035) : *Domain Names - Implementation and Specification* (Spécification historique du protocole DNS).
* [RFC 4033, 4034, 4035 (2005)](https://datatracker.ietf.org/doc/html/rfc4033) : *DNS Security Introduction and Requirements* (Fondations cryptographiques de **DNSSEC**).
* [RFC 7816 (2016)](https://datatracker.ietf.org/doc/html/rfc7816) : *DNS Query Name Minimisation to Improve Privacy* (**QNAME Minimization**).
* [RFC 7858 (2016)](https://datatracker.ietf.org/doc/html/rfc7858) : *Specification for DNS over Transport Layer Security* (**DoT** - Port 853).
* [RFC 8484 (2018)](https://datatracker.ietf.org/doc/html/rfc8484) : *DNS Queries over HTTPS* (**DoH** - Port 443).
* [RFC 8914 (2020)](https://datatracker.ietf.org/doc/html/rfc8914) : *Extended DNS Errors* (Signalement précis des causes d'échec DNSSEC).

### Documentations Officielles des Moteurs Utilisés
* [Documentation Officielle PowerDNS DNSdist](https://dnsdist.org/) : Architecture du proxy haute performance, moteur de filtrage Lua, anti-DDoS.
* [Documentation Officielle NLnet Labs Unbound](https://nlnetlabs.nl/documentation/unbound/) : Moteur récursif validant, durcissement et ancres de confiance DNSSEC.
* [DNS Flag Day 2020](https://dnsflagday.net/2020/) : Recommandation internationale de la taille de tampon EDNS à 1232 octets contre la fragmentation IP.

---

## 3. L'Architecture Expliquée aux Cadets : Le Modèle "Bouclier & Cerveau"

Dans l'industrie, exposer un résolveur DNS directement sur Internet est une grave erreur d'architecture. Nous utilisons le modèle **Two-Tier** :

```
                          [ ATTAQUES INTERNET & REQUÊTES CLIENTS ]
                                              │
                                              ▼
                      ┌───────────────────────────────────────────────┐
                      │    LE BOUCLIER : DNSdist (Frontline Proxy)    │
                      │  • Encaisse les requêtes massives (C++ epoll) │
                      │  • Détruit les attaques DDoS (Drop ANY)       │
                      │  • Négocie le chiffrement TLS (DoH & DoT)     │
                      │  • Expose la télémétrie (Port 8083)           │
                      └───────────────────────┬───────────────────────┘
                                              │ Réseau interne privé
                                              │ (172.28.0.2:53)
                                              ▼
                      ┌───────────────────────────────────────────────┐
                      │    LE CERVEAU : Unbound (Moteur Récursif)     │
                      │  • Parcourt la hiérarchie mondiale (Racine)   │
                      │  • Vérifie les signatures cryptographiques    │
                      │  • Bloque les malwares (Threat Sinkhole)      │
                      │  • Protège la vie privée (QNAME Minimization) │
                      └───────────────────────────────────────────────┘
```

---

## 4. Guide Pratique de Déploiement Pas-à-Pas (Hands-On)

Accompagnez vos cadets en déroulant ces étapes une par une sur la machine ou la Raspberry Pi.

---

### Étape 1 : Diagnostic Préalable du Système
> **Pourquoi cette étape ?**  
> Vérifier la présence des conteneurs et s'assurer qu'aucun service local (comme `systemd-resolved`) ne squatte le port 53.

```bash
# 1. Vérification de Docker et Docker Compose
docker --version && docker compose version

# 2. Vérification des ports 53, 853, 443 et 3000
ss -tuln | grep -E ':(53|853|443|3000)\b'
```

* **Sortie attendue :** Aucune ligne retournée (les ports sont libres).
* **Si le port 53 est occupé par `systemd-resolved` :**
  ```bash
  sudo sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
  sudo systemctl restart systemd-resolved
  ```

---

### Étape 2 : Préparation de l'Arborescence
> **Pourquoi cette étape ?**  
> Isoler proprement les configurations, certificats, scripts et listes de menaces.

```bash
mkdir -p ~/hack/dnsaton/{unbound,dnsdist,certs,blocklists,scripts}
mkdir -p ~/hack/dnsaton/monitoring/{prometheus,grafana/provisioning/datasources,grafana/provisioning/dashboards,grafana/dashboards}
cd ~/hack/dnsaton
```

---

### Étape 3 : Génération des Clés et Certificats TLS (DoH & DoT)
> **Pourquoi cette étape ?**  
> Les protocoles DoH (port 443) et DoT (port 853) exigent un certificat x509 valide. Nous générons une paire de clés RSA 2048 bits avec extensions SAN (*Subject Alternative Name*).

Exécutez la commande :
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=dnsaton.local/O=DNSaton Security/C=FR" \
  -addext "subjectAltName=DNS:localhost,DNS:dnsaton.local,IP:127.0.0.1"

chmod 644 certs/server.key certs/server.crt
```

* **Ce qui se passe :** OpenSSL crée la clé privée `server.key` et le certificat public `server.crt`.
* **Contrôle cadet :** `openssl x509 -in certs/server.crt -text -noout | grep -A 1 "Subject Alternative Name"` doit afficher `DNS:localhost, DNS:dnsaton.local, IP:127.0.0.1`.

---

### Étape 4 : Configuration du Moteur Récursif Unbound
> **Pourquoi cette étape ?**  
> Unbound est configuré avec les directives de sécurité les plus strictes de l'IETF.

Créez le fichier `unbound/unbound.conf` :
```yaml
server:
    verbosity: 1
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    num-threads: 2

    # Contrôle d'accès : Unbound ne répond qu'au réseau Docker interne
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow

    # Intégrité DNSSEC obligatoire
    auto-trust-anchor-file: "/opt/unbound/etc/unbound/var/root.key"
    val-clean-additional: yes
    val-permissive-mode: no

    # Vie privée & Anti-reconnaissance
    qname-minimisation: yes
    hide-identity: yes
    hide-version: yes

    # Durcissement anti-poisoning de cache (Kaminsky)
    use-caps-for-id: yes         # Encodage 0x20 bit
    outgoing-range: 8192

    # Prévention fragmentation IP (DNS Flag Day)
    edns-buffer-size: 1232
    max-udp-size: 1232

    # Cache et Threat Intelligence
    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    include: "/opt/unbound/etc/unbound/blocklists/*.conf"
```

---

### Étape 5 : Mise en Place du Threat Sinkholing
> **Pourquoi cette étape ?**  
> Démontrer aux cadets comment neutraliser préventivement un malware ou une campagne de phishing au niveau DNS avant même que la connexion réseau ne s'établisse.

Créez `blocklists/threats.conf` :
```apache
local-zone: "malware-test.evil.local" redirect
local-data: "malware-test.evil.local A 0.0.0.0"

local-zone: "phishing-bank.fake.local" redirect
local-data: "phishing-bank.fake.local A 0.0.0.0"
```

---

### Étape 6 : Configuration du Bouclier DNSdist
> **Pourquoi cette étape ?**  
> DNSdist écoute sur tous les ports publics (53, 853, 443), termine le TLS et détruit les paquets dangereux.

Créez `dnsdist/dnsdist.conf` :
```lua
-- Interfaces d'écoute
setLocal("0.0.0.0:53", { reusePort=true })
addTLSLocal("0.0.0.0:853", "/etc/dnsdist/certs/server.crt", "/etc/dnsdist/certs/server.key")
addDOHLocal("0.0.0.0:443", "/etc/dnsdist/certs/server.crt", "/etc/dnsdist/certs/server.key", {"/dns-query"}, { reusePort=true })

-- Autorisation des requêtes de tous les réseaux
addACL("0.0.0.0/0")
addACL("::/0")

-- Console Web & Métriques Prometheus
webserver("0.0.0.0:8083")
setWebserverConfig({password="hackathon2026", apiKey="hackathon2026", statsRequireAuthentication=false, acl="0.0.0.0/0, ::/0"})

-- Liaison vers le backend Unbound
newServer({
    address="172.28.0.2:53",
    name="unbound-backend",
    checkInterval=2,
    checkTimeout=1000,
    maxCheckFailures=3,
    mustResolve=false
})

-- Règles de Sécurité Anti-DDoS
-- 1. Destruction immédiate des requêtes ANY (anti-amplification)
addAction(QTypeRule(DNSQType.ANY), DropAction())

-- 2. Bridation dynamique par IP source
addAction(MaxQPSIPRule(50, 32, 64), DelayAction(100))
addAction(MaxQPSIPRule(150, 32, 64), DropAction())

-- 3. Bannissement automatique des floods
local dbr = dynBlockRulesGroup()
dbr:setQueryRate(100, 10, "Exceeded query rate limit", 60)
dbr:setRCodeRate(DNSRCode.SERVFAIL, 20, 10, "Exceeded SERVFAIL rate limit", 60)

function maintenance()
    dbr:apply()
end
```

---

### Étape 7 : Lancement avec Docker Compose
> **Pourquoi cette étape ?**  
> Déployer l'infrastructure complète en une seule commande reproductible.

Lancez la commande :
```bash
docker compose up -d
docker compose ps
```

* **Sortie attendue :** 4 conteneurs à l'état `Up` :
  * `dnsaton-unbound` (172.28.0.2)
  * `dnsaton-dnsdist` (172.28.0.3, ports 53, 853, 443, 8083)
  * `dnsaton-prometheus` (172.28.0.4, port 9090)
  * `dnsaton-grafana` (172.28.0.5, port 3000)

---

## 5. Ateliers Pratiques pour les Cadets (Travaux Pratiques / Démonstrations)

Faites exécuter ces 4 travaux pratiques à vos cadets pour ancrer la compréhension théorique par la manipulation.

---

### TP 1 : La Preuve Cryptographique DNSSEC
**Objectif :** Vérifier la différence entre un domaine valide et un domaine falsifié.

1. **Test sur domaine authentique :**
   ```bash
   dig @127.0.0.1 -p 53 cloudflare.com +dnssec
   ```
   * **Ce qu'il faut observer :** Dans la section `flags:`, le drapeau **`ad`** (*Authenticated Data*) est présent. Cela prouve qu'Unbound a validé cryptographiquement la signature jusqu'à la racine mondiale.
2. **Test sur domaine altéré (Simulation d'usurpation DNS) :**
   ```bash
   dig @127.0.0.1 -p 53 dnssec-failed.org
   ```
   * **Ce qu'il faut observer :** `status: SERVFAIL`. Le résolveur refuse catégoriquement de renvoyer l'adresse IP frauduleuse à l'utilisateur.

---

### TP 2 : Interception d'une Requête DoH (Port 443)
**Objectif :** Comprendre comment fonctionne le DNS chiffré dans HTTPS (RFC 8484).

Exécutez une requête HTTP/2 binaire avec `curl` :
```bash
# Génération de la question DNS "example.com" en Base64URL
B64=$(printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | base64 | tr '/+' '_-' | tr -d '=')

# Requête HTTPS vers DNSdist
curl -ks "https://127.0.0.1/dns-query?dns=${B64}" -H "Accept: application/dns-message" | hexdump -C
```
* **Ce qu'il faut observer :** Une réponse binaire chiffrée en TLS arrive sur le port 443. Pour les équipements réseau intermédiaires, cette trame est indiscernable d'une navigation web classique.

---

### TP 3 : Neutralisation de l'Amplification DDoS (Requête ANY)
**Objectif :** Démontrer comment DNSdist protège l'infrastructure contre le détournement.

Exécutez une requête de type `ANY` :
```bash
dig @127.0.0.1 -p 53 cloudflare.com ANY +time=2 +tries=1
```
* **Ce qu'il faut observer :** `connection timed out` ou `no servers could be reached`.
* **Explication pour les cadets :** DNSdist a intercepté la requête grâce à la règle `QTypeRule(DNSQType.ANY)` et l'a immédiatement détruite (`DropAction`) sans aucune réponse, empêchant l'attaquant d'utiliser le serveur pour inonder une victime.

---

### TP 4 : Supervision en Direct sur Grafana
**Objectif :** Visualiser l'impact des attaques et du trafic légitime sur un SOC.

1. Ouvrez dans le navigateur : `http://localhost:3000` (ou `http://<IP_LOCAL>:3000`).
2. Lancez le simulateur de trafic en tâche de fond :
   ```bash
   ./scripts/traffic-generator.sh
   ```
3. Observez en temps réel :
   * La courbe verte des requêtes DoH monter.
   * La courbe rouge des attaques bloquées réagir aux requêtes `ANY`.
   * La latence moyenne du résolveur Unbound rester sous les 15 millisecondes.

---

## 6. Guide de Dépannage & FAQ pour les Cadets

### Q1 : Pourquoi mon téléphone n'arrive pas à utiliser le DoT (Port 853) avec l'IP brute ?
* **Réponse :** Android ("DNS privé") exige un **Nom de Domaine Qualifié (FQDN)** et non une adresse IP brute, ainsi qu'un certificat TLS signé par une autorité reconnue (ex. Let's Encrypt). Pour un test en laboratoire local sur IP, on utilise le DNS standard (port 53 UDP) ou un client DoT acceptant les certificats auto-signés.

### Q2 : Pourquoi le statut `SERVFAIL` est-il une victoire pour notre résolveur ?
* **Réponse :** Dans le monde DNS classique, `SERVFAIL` signifie souvent une panne. Mais dans le cadre de DNSSEC, un `SERVFAIL` face à un domaine comme `dnssec-failed.org` est **la preuve absolue que le mécanisme de défense fonctionne** : il a détecté une signature mathématique corrompue et a préféré couper l'accès plutôt que de laisser l'utilisateur être redirigé vers un site pirate.

### Q3 : Pourquoi avoir bridé la taille des paquets EDNS à 1232 octets ?
* **Réponse :** La norme Ethernet standard impose un MTU (*Maximum Transmission Unit*) de 1500 octets. Avec les en-têtes IP (20 octets IPv4 ou 40 octets IPv6) et UDP (8 octets), ainsi que certains tunnels VPN, les paquets DNS de plus de 1232 octets risquent d'être fragmentés par les routeurs. Les paquets IP fragmentés sont fréquemment bloqués par les pare-feux ou exploités pour des attaques d'injection de paquets. 1232 octets est la recommandation universelle du *DNS Flag Day 2020*.
