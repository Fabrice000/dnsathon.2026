# DNSaton sur Raspberry Pi — Guide de déploiement natif

**Objet :** reproduire la configuration du `docker-compose.yml` sur des Raspberry Pi, **en tenant compte du guide `dnsathon-activite1.pdf`** (lab DNS, VLAN 40, quatre points notés par le jury, trois livrables).

> Ce document remplace le script `deploy-raspberrypi.sh` : toutes les commandes sont données **une par une**, avec la raison du geste, comme dans le guide d'activité. Aucun connecteur de documents n'étant disponible dans cette session, le fichier est fourni en Markdown (exportable en Word/PDF si besoin).

---

## 0. Arbitrage : deux profils, un même socle Unbound

Le guide d'activité et le docker-compose ne visent pas exactement la même chose :

| Exigence | Guide d'activité (PDF) | docker-compose DNSaton |
|---|---|---|
| Résolveur | Unbound directement exposé sur le VLAN | Unbound caché derrière DNSdist |
| Preuve d'ACL | `dig` depuis un autre VLAN → `REFUSED` | DNSdist filtre avant de transmettre |
| Rate limiting | `ip-ratelimit` / `ratelimit` dans Unbound | `MaxQPSIPRule` + dynBlock dans DNSdist |
| Logs | `/var/log/unbound/unbound.log`, `log-queries` | Métriques Prometheus/Grafana |
| Transport | DNS classique 53 | DoH 443, DoT 853, DNS 53 |

**Conflit à connaître :** si DNSdist est placé devant Unbound, les requêtes arrivent à Unbound avec pour source `127.0.0.1`. Le test `REFUSED` depuis un autre VLAN ne peut donc **pas** être fait au niveau d'Unbound : il faut le faire au niveau de DNSdist (`addACL`).

**Décision :** le socle Unbound est identique dans les deux cas ; seuls l'écoute et l'ACL changent.

- **Profil A — Lab / jury (recommandé pour l'activité 1).** Unbound écoute sur `0.0.0.0:53`, ACL `192.168.40.0/24` + monitoring, `REFUSED` visible depuis l'extérieur. C'est le profil qui coche les 4 points notés.
- **Profil B — Stack DNSaton complète.** Unbound en backend `127.0.0.1:5353`, DNSdist en front sur `53/853/443/8083`, Prometheus + Grafana. C'est l'équivalent exact du docker-compose, avec le chiffrement et le monitoring en plus.

> **Conseil :** déploie le **Profil A** sur Resolver 1 et 2 pour la soutenance, puis ajoute le **Profil B** sur Resolver 1 si tu veux présenter la couche DoH/DoT et Grafana.

---

## 1. Objectifs et points notés (rappel du PDF)

1. **Réponses légitimes correctes** → `NOERROR` + section `ANSWER`.
2. **DNSSEC actif et fonctionnel** → drapeau `ad` sur un domaine valide, `SERVFAIL` sur `dnssec-failed.org`.
3. **Rate limiting démontrable** → compteur `ratelimit` qui grimpe pendant `dnsperf`.
4. **Logs qui révèlent un abus** → IP source visible dans `unbound.log`.

**Livrables :** le résolveur testable (IP donnée au jury), le document des mesures de sécurité, la démo live de résistance.

---

## 2. Architecture

### Profil A — conforme au guide

```text
 VLAN 40 (192.168.40.x)   VLAN 50 (monitoring)   Autres VLAN / Internet
        |                        |                         |
        +--------- allow --------+                         | refuse
        v                                                  v
 +--------------------------------------------------------------+
 |  Raspberry Pi "Resolver 1" — Unbound 0.0.0.0:53              |
 |  DNSSEC | durcissement | rate limiting | logs | remote-control|
 +--------------------------------------------------------------+
        | résolution récursive vers les racines du lab / Internet
        v
 Racines / TLD / autoritaires
```

### Profil B — équivalent docker-compose

```text
 Clients --53/853/443--> DNSdist (0.0.0.0) --127.0.0.1:5353--> Unbound --> racines
                             | 8083
                             v
                        Prometheus :9090 --> Grafana :3000
```

**Mappage Docker → natif :**

| docker-compose | Raspberry Pi |
|---|---|
| réseau `172.28.0.0/24` | boucle locale `127.0.0.1` |
| Unbound `172.28.0.2:53` | Profil A : `0.0.0.0:53` / Profil B : `127.0.0.1:5353` |
| DNSdist `172.28.0.3` | `0.0.0.0:53/853/443/8083` |
| `prometheus:9090` | `127.0.0.1:9090` |
| `grafana:3000` | `0.0.0.0:3000` |
| `dnsdist:8083` | `127.0.0.1:8083` |

---

## 3. Préparation de la machine

### 3.1 Connexion SSH et repérage

```bash
ssh j4y3@192.168.40.11          # identifiant et IP donnés à votre table
sudo -i                         # session root pour enchaîner les commandes
ip a                            # noter l'IP exacte du Resolver (ex. 192.168.40.11)
```

*Pourquoi :* c'est cette IP qu'on donne au jury et qu'on met dans `interface` / `access-control` en Profil A.

### 3.2 Installer les outils

```bash
apt update
apt install -y unbound unbound-anchor dnsutils knot-dnsutils dnsperf dnstop tcpdump
```

| Paquet | Rôle |
|---|---|
| `unbound`, `unbound-anchor` | résolveur + clé racine DNSSEC |
| `dnsutils` | `dig`, `delv` — preuves du jury |
| `knot-dnsutils` | `kdig`, vue détaillée en secours |
| `dnsperf` | génération de charge pour la démo |
| `dnstop`, `tcpdump` | observation du trafic en direct |

*Si `unbound-anchor` n'existe pas sur la version :* le binaire est inclus dans `unbound` sur Debian récent ; vérifier avec `which unbound-anchor`.

### 3.3 Sauvegarder et créer les dossiers

```bash
cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak
mkdir -p /var/lib/unbound /var/log/unbound
chown unbound:unbound /var/lib/unbound /var/log/unbound
```

*Pourquoi :* on garde la config d'origine en secours, et Unbound doit pouvoir écrire sa clé racine et son log.

### 3.4 Générer l'ancre de confiance DNSSEC

```bash
unbound-anchor -a /var/lib/unbound/root.key
chown unbound:unbound /var/lib/unbound/root.key
```

*Pourquoi :* `root.key` contient la clé publique de la racine, point de départ de la chaîne de confiance. Sans elle : `root.key: No such file` et le point noté 2 est impossible.

### 3.5 Activer le contrôle et libérer le port 53

```bash
unbound-control-setup                    # clés pour unbound-control
```

Sur Profil B uniquement, DNSdist occupe le port 53. Libérer le stub système :

```bash
sed -i 's/^DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
grep -q '^DNSStubListener=' /etc/systemd/resolved.conf || echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf
systemctl restart systemd-resolved
```

Puis, **impérativement**, réorienter la résolution locale du Pi (sinon `apt` ne résout plus rien) :

```bash
grep -q 127.0.0.53 /etc/resolv.conf && ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

---

## 4. Configuration Unbound — socle commun

On n'écrase pas le gros fichier principal : on dépose un fichier dans `/etc/unbound/unbound.conf.d/`, lu automatiquement par la config Debian/Raspbian.

```bash
nano /etc/unbound/unbound.conf.d/dnsathon.conf
```

### 4.1 Tableau mesure → risque couvert

| Risque (PDF §1.2) | Directive | Effet |
|---|---|---|
| Amplification DDoS | `access-control`, `deny-any`, `minimal-responses` | REFUSED hors VLAN, plus de réponse ANY, réponses courtes |
| Cache poisoning | `auto-trust-anchor-file`, `val-clean-additional`, `use-caps-for-id`, `harden-glue`, `harden-dnssec-stripped`, `harden-referral-path`, `harden-algo-downgrade`, `unwanted-reply-threshold` | validation DNSSEC + 0x20 + glue et délégations strictes |
| Abus / surcharge | `ip-ratelimit`, `ratelimit`, logs | bridage par client et par domaine, source identifiable |
| Fuite de métadonnées | `qname-minimisation`, `hide-identity`, `hide-version` | minimalisme et anonymat |
| Fragmentation IP | `edns-buffer-size: 1232`, `max-udp-size: 1232` | conformité DNS Flag Day (apport docker-compose) |

### 4.2 Fichier complet — Profil A (lab / jury)

À coller sur **Resolver 1** (`192.168.40.11`). Remplacer `192.168.40.0/24` par le VLAN annoncé si besoin ; ajouter `192.168.50.0/24` pour le monitoring.

```unboundconf
server:
    # --- Interfaces et ports (PDF 4.1) ---
    interface: 0.0.0.0
    interface: ::0
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

    # --- ACL : qui a le droit d'interroger (PDF 4.2) ---
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    access-control: 192.168.40.0/24 allow
    access-control: 192.168.50.0/24 allow

    # --- DNSSEC (PDF 4.3) ---
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no

    # --- Durcissement (PDF 4.4) ---
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    use-caps-for-id: yes
    qname-minimisation: yes
    minimal-responses: yes
    deny-any: yes
    rrset-roundrobin: yes
    unwanted-reply-threshold: 10000000

    # --- Anti-fragmentation (apport docker-compose) ---
    edns-buffer-size: 1232
    max-udp-size: 1232

    # --- Rate limiting (PDF 4.5) ---
    ip-ratelimit: 200
    ratelimit: 1000

    # --- Cache et performance (PDF 4.6) ---
    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    num-threads: 2
    so-reuseport: yes
    msg-cache-size: 64m
    rrset-cache-size: 128m
    infra-cache-numhosts: 10000

    # --- Journalisation (PDF 4.7) ---
    verbosity: 1
    use-syslog: no
    logfile: "/var/log/unbound/unbound.log"
    log-queries: yes
    log-replies: yes
    log-servfail: yes
    extended-statistics: yes

remote-control:
    control-enable: yes
```

**Points d'attention :**

- Le préfixe **le plus précis gagne** : `0.0.0.0/0 refuse` sert de filet, les `allow` plus précis passent dessus.
- `ip-ratelimit: 200` limite par **IP cliente** ; `ratelimit: 1000` limite par **domaine de destination**. Les deux se complètent.
- `use-caps-for-id` peut gêner un serveur mal configuré ; si un domaine ne répond plus, passer à `no` et recharger.
- Si aucun log n'apparaît (AppArmor), passer `use-syslog: yes` et lire avec `journalctl -u unbound -f`.

### 4.3 Fichier complet — Profil B (derrière DNSdist)

Unbound n'écoute que sur la boucle locale. L'ACL ne laisse passer que DNSdist.

```unboundconf
server:
    interface: 127.0.0.1
    port: 5353
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    num-threads: 2

    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow

    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no

    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    use-caps-for-id: yes
    qname-minimisation: yes
    minimal-responses: yes
    deny-any: yes
    rrset-roundrobin: yes
    unwanted-reply-threshold: 10000000

    edns-buffer-size: 1232
    max-udp-size: 1232

    ip-ratelimit: 200
    ratelimit: 1000

    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    so-reuseport: yes
    msg-cache-size: 64m
    rrset-cache-size: 128m

    verbosity: 1
    use-syslog: no
    logfile: "/var/log/unbound/unbound.log"
    log-queries: yes
    log-replies: yes
    log-servfail: yes
    extended-statistics: yes

    # Sinkhole Threat Intelligence (apport docker-compose)
    include: "/etc/unbound/blocklists/*.conf"

remote-control:
    control-enable: yes
```

Le sinkhole (facultatif, repris du docker-compose) :

```bash
mkdir -p /etc/unbound/blocklists
cat > /etc/unbound/blocklists/threats.conf <<'EOF'
local-zone: "malware-test.evil.local" redirect
local-data: "malware-test.evil.local A 0.0.0.0"
local-data: "malware-test.evil.local AAAA ::"

local-zone: "phishing-bank.fake.local" redirect
local-data: "phishing-bank.fake.local A 0.0.0.0"
local-data: "phishing-bank.fake.local AAAA ::"

local-zone: "ransomware-c2.test" redirect
local-data: "ransomware-c2.test A 0.0.0.0"
local-data: "ransomware-c2.test AAAA ::"
EOF
chown root:unbound /etc/unbound/blocklists/threats.conf
chmod 640 /etc/unbound/blocklists/threats.conf
```

> Sur Debian/Raspbian, le fichier principal `/etc/unbound/unbound.conf` contient déjà `include: "/etc/unbound/unbound.conf.d/*.conf"`. Si ta version ne l'a pas, ajoute la ligne ou colle le bloc `server:` directement dans le fichier principal (après sauvegarde).

### 4.4 Vérifier et démarrer

```bash
unbound-checkconf                       # doit afficher : no errors
systemctl enable --now unbound
systemctl status unbound                # doit être : active (running)
```

*Pourquoi :* on vérifie **avant** chaque redémarrage ; une faute de frappe laisserait le résolveur mort devant le jury.

---

## 5. Profil B — DNSdist, Prometheus et Grafana (équivalent docker-compose)

### 5.1 Certificats TLS (DoH / DoT)

```bash
apt install -y dnsdist
mkdir -p /etc/dnsdist/certs
PI_IP=$(hostname -I | awk '{print $1}')
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/dnsdist/certs/server.key \
  -out    /etc/dnsdist/certs/server.crt \
  -subj "/CN=dnsaton.local/O=Hackathon DNS Resolver/C=FR" \
  -addext "subjectAltName=DNS:localhost,DNS:$(hostname),DNS:dnsaton.local,IP:127.0.0.1,IP:${PI_IP}"
```

*Pourquoi :* le certificat doit contenir les **SAN** du nom et de l'IP du Pi, sinon les clients DoH/DoT refusent la connexion.

Rendre la clé lisible par le service (utilisateur `_dnsdist` sur Debian) :

```bash
chown root:_dnsdist /etc/dnsdist/certs/server.key
chmod 640 /etc/dnsdist/certs/server.key
chmod 644 /etc/dnsdist/certs/server.crt
```

Si l'utilisateur n'existe pas, vérifier avec `systemctl cat dnsdist.service | grep User=` et adapter, sinon `chmod 644` la clé.

### 5.2 DNSdist

```bash
nano /etc/dnsdist/dnsdist.conf
```

```lua
-- Interfaces d'écoute
setLocal("0.0.0.0:53", { reusePort=true })
addTLSLocal("0.0.0.0:853", "/etc/dnsdist/certs/server.crt", "/etc/dnsdist/certs/server.key")
addDOHLocal("0.0.0.0:443", "/etc/dnsdist/certs/server.crt", "/etc/dnsdist/certs/server.key", {"/dns-query"}, { reusePort=true })

-- ACL : dans ce profil, c'est DNSdist qui filtre (Unbound ne voit que 127.0.0.1)
addACL("192.168.40.0/24")
addACL("192.168.50.0/24")
addACL("127.0.0.0/8")
-- Pour un résolveur réellement public, remplacer les trois lignes ci-dessus par :
-- addACL("0.0.0.0/0"); addACL("::/0")

-- Console web et métriques
webserver("0.0.0.0:8083")
setWebserverConfig({password="hackathon2026", apiKey="hackathon2026", statsRequireAuthentication=false, acl="0.0.0.0/0, ::/0"})

-- Backend : Unbound local
newServer({
    address="127.0.0.1:5353",
    name="unbound-backend",
    checkInterval=2,
    checkTimeout=1000,
    maxCheckFailures=3,
    mustResolve=false
})

-- Anti-DDoS (équivalent et complément du durcissement Unbound)
addAction(QTypeRule(DNSQType.ANY), DropAction())
addAction(MaxQPSIPRule(50, 32, 64), DelayAction(100))
addAction(MaxQPSIPRule(150, 32, 64), DropAction())

local dbr = dynBlockRulesGroup()
dbr:setQueryRate(100, 10, "Exceeded query rate limit", 60)
dbr:setRCodeRate(DNSRCode.SERVFAIL, 20, 10, "Exceeded SERVFAIL rate limit", 60)

function maintenance()
    dbr:apply()
end
```

```bash
systemctl enable --now dnsdist
```

### 5.3 Prometheus

```bash
apt install -y prometheus
cat > /etc/prometheus/prometheus.yml <<'EOF'
global:
  scrape_interval: 2s
  evaluation_interval: 2s

scrape_configs:
  - job_name: "dnsdist"
    static_configs:
      - targets: ["127.0.0.1:8083"]
EOF
systemctl enable --now prometheus
```

### 5.4 Grafana

```bash
curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana.gpg
case "$(uname -m)" in
  aarch64|arm64) A=arm64 ;;
  armv7l|armhf)  A=armhf ;;
  *)             A=amd64 ;;
esac
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg arch=${A}] https://packages.grafana.com/oss/deb stable main" \
  > /etc/apt/sources.list.d/grafana.list
apt update && apt install -y grafana
```

Datasource (remplace `http://prometheus:9090` du Docker) :

```bash
mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
cat > /etc/grafana/provisioning/datasources/datasource.yml <<'EOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
EOF
```

```bash
cat > /etc/grafana/provisioning/dashboards/dashboards.yml <<'EOF'
apiVersion: 1
providers:
  - name: "DNSaton Dashboards"
    orgId: 1
    folder: ""
    type: file
    disableDeletion: false
    updateIntervalSeconds: 5
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF
```

Copier le dashboard `monitoring/grafana/dashboards/dns-overview.json` du projet vers `/var/lib/grafana/dashboards/`, puis :

```bash
chown -R grafana:grafana /var/lib/grafana/dashboards
mkdir -p /etc/systemd/system/grafana-server.service.d
cat > /etc/systemd/system/grafana-server.service.d/dnsaton.conf <<'EOF'
[Service]
Environment="GF_SECURITY_ADMIN_USER=admin"
Environment="GF_SECURITY_ADMIN_PASSWORD=admin"
Environment="GF_USERS_ALLOW_SIGN_UP=false"
Environment="GF_AUTH_ANONYMOUS_ENABLED=true"
Environment="GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer"
EOF
systemctl daemon-reload
systemctl enable --now grafana-server
```

---

## 6. Vérification et preuves pour le jury

### Point 1 — réponses légitimes correctes

```bash
dig @127.0.0.1 example.com
```

Attendu : `status: NOERROR` et une section `ANSWER` avec des IP. Si le premier `dig` expire, cache vide : relancer, la réponse suivante vient en 0 ms.

### Point 2 — DNSSEC actif et fonctionnel

```bash
dig @127.0.0.1 example.com +dnssec | grep -E "flags|status"
dig @127.0.0.1 dnssec-failed.org +time=15 +tries=1
delv @127.0.0.1 example.com
delv @127.0.0.1 dnssec-failed.org
```

Attendu : drapeau `ad` sur `example.com`, `SERVFAIL` sur `dnssec-failed.org`, `fully validated` puis `resolution failed` avec `delv`.

### Point 3 preuve d'ACL (Profil A uniquement)

Depuis une machine **hors** du VLAN autorisé :

```bash
dig @192.168.40.11 google.com        # doit renvoyer : status: REFUSED
```

Depuis une IP autorisée, la même requête répond normalement. Ce contraste est la démonstration.

> En Profil B, faire le même test au niveau de DNSdist : une IP non listée dans `addACL` n'obtient pas de réponse.

### Point 4 — logs et compteurs

```bash
unbound-control status
tail -f /var/log/unbound/unbound.log
unbound-control stats_noreset | grep -E "ratelimit|num.query|requestlist"
```

Chaque ligne de log porte l'IP source, l'heure et le nom demandé : une IP qui envoie des milliers de requêtes par seconde saute aux yeux.

---

## 7. Démo de résistance (point noté 3)

> **Règle d'or :** ces tests de charge uniquement dans le réseau isolé du lab, sur notre propre infrastructure, et toujours en accord avec le mentor. Jamais vers un service tiers sur Internet.

Préparer un flux de requêtes :

```bash
printf 'example.com A\nwww.google.com A\nisc.org A\n' > requetes.txt
```

Observer d'un côté :

```bash
dnstop -l 3 eth0
tail -f /var/log/unbound/unbound.log
```

Générer la charge de l'autre :

```bash
dnsperf -s 192.168.40.11 -d requetes.txt -c 50 -Q 20000 -l 15
```

Vérifier l'anti-amplification et le bridage :

```bash
dig @192.168.40.11 isc.org ANY       # réponse minimale, pas d'amplification
unbound-control stats_noreset | grep ratelimit
```

On compare le compteur **avant** et **pendant** la charge : il grimpe, preuve que le plafond entre en jeu. Pendant ce temps, un `dig` normal depuis une IP autorisée continue de répondre vite.

En Profil B, les compteurs complémentaires sont visibles ici :

```bash
curl -s http://127.0.0.1:8083/metrics | grep '^dnsdist_'
```

---

## 8. Réplication sur Resolver 2

Deux résolveurs identiques = base de la redondance et de l'anycast (activité 5).

```bash
# Depuis Resolver 1
scp /etc/unbound/unbound.conf.d/dnsathon.conf j4y3@192.168.40.12:/tmp/

# Sur Resolver 2
mkdir -p /var/lib/unbound /var/log/unbound
chown unbound:unbound /var/lib/unbound /var/log/unbound
unbound-anchor -a /var/lib/unbound/root.key
chown unbound:unbound /var/lib/unbound/root.key
unbound-control-setup
cp /tmp/dnsathon.conf /etc/unbound/unbound.conf.d/dnsathon.conf
```

Adapter l'IP dans `interface` / `access-control` (Profil A), puis :

```bash
unbound-checkconf && systemctl enable --now unbound
dig @192.168.40.12 example.com
```

---

## 9. Livrables et checklist finale

**Livrables :**
1. Le résolveur testable : son IP (ex. `192.168.40.11`) communiquée au jury.
2. Ce document des mesures de sécurité (tableau §4.1).
3. La démo live de résistance à un abus simulé (§7).

**Checklist avant de montrer :**

- [ ] L'IP du résolveur est notée et donnée au jury.
- [ ] `dig example.com` depuis une IP autorisée répond `NOERROR`.
- [ ] `dig` depuis l'extérieur répond `REFUSED`.
- [ ] `example.com +dnssec` montre `ad` ; `dnssec-failed.org` donne `SERVFAIL`.
- [ ] Le test de charge fait grimper le compteur `ratelimit`.
- [ ] Le log affiche l'IP source d'un abus.
- [ ] Resolver 1 et Resolver 2 répondent tous les deux.
- [ ] *(Profil B)* `8083/metrics`, `9090` et `3000` accessibles.

---

## 10. Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| `root.key: No such file` | ancre non générée | `unbound-anchor -a /var/lib/unbound/root.key` + `chown unbound:unbound` |
| `unbound-checkconf` signale une ligne | faute de frappe | corriger avant tout redémarrage |
| Port 53 déjà pris | `systemd-resolved` (Profil B) | `DNSStubListener=no` + redémarrer + réorienter `/etc/resolv.conf` |
| Aucun log écrit | AppArmor bloque `/var/log/unbound` | `use-syslog: yes` puis `journalctl -u unbound -f` |
| Client DoH/DoT refuse le certificat | certificat auto-signé | ajouter l'exception client ou installer un certificat signé |
| Un domaine ne répond plus | `use-caps-for-id` trop strict | passer à `no` et `systemctl reload unbound` |
| `apt` ne résout plus après coupure du stub | `/etc/resolv.conf` pointe sur `127.0.0.53` | `ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf` |

**Commandes d'exploitation utiles :**

```bash
systemctl status unbound dnsdist prometheus grafana-server
systemctl reload unbound
unbound-control stats_noreset | grep ratelimit
journalctl -u unbound -f
curl -s http://127.0.0.1:8083/metrics | grep -c '^dnsdist_'
```

---

## 11. Conclusion

Le socle Unbound couvre les quatre points notés : il répond aux clients légitimes, refuse les inconnus, valide DNSSEC, encaisse un abus sans tomber et le journalise. Le Profil B ajoute la couche du docker-compose — chiffrement DoH/DoT, anti-DDoS complémentaire et supervision Grafana — sans affaiblir ce socle. La configuration reste identique sur Resolver 1 et 2, prête à être branchée aux autres activités (zone signée, analyse Blue Team, anycast).
