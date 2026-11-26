#!/usr/bin/env bash
# ==============================================================================
# DNSaton — Déploiement NATIF sur Raspberry Pi (sans Docker)
# ------------------------------------------------------------------------------
# Reproduit exactement la pile du docker-compose.yml :
#   Unbound (récursif durci)  -> 127.0.0.1:5353  (équivalent 172.28.0.2:53)
#   DNSdist  (frontend DoH/DoT/anti-DDoS) -> 0.0.0.0:53/443/853/8083
#   Prometheus -> 127.0.0.1:9090   (scrape dnsdist:8083 -> 127.0.0.1:8083)
#   Grafana    -> 0.0.0.0:3000     (datasource prometheus:9090 -> 127.0.0.1:9090)
#
# L'isolation "Two-Tier" est conservée : Unbound n'écoute QUE sur la boucle
# locale (127.0.0.1), donc aucun client réseau ne peut l'interroger directement.
#
# Usage (sur le Pi) :
#   sudo bash deploy-raspberrypi.sh
#
# Compatible : Raspberry Pi 4/5 (arm64), Pi 3/Zero 2 (armhf), x86_64 (test).
# ==============================================================================
set -euo pipefail

# ------------------------------------------------------------------ couleurs
C_CYAN="\033[0;36m"; C_GREEN="\033[0;32m"; C_YELLOW="\033[1;33m"
C_RED="\033[0;31m";  C_RESET="\033[0m"
info()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
ok()    { echo -e "${C_GREEN}[ OK ]${C_RESET}  $*"; }
warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*"; }
die()   { echo -e "${C_RED}[ERREUR]${C_RESET} $*" >&2; exit 1; }
step()  { echo -e "\n${C_CYAN}=== $* ===${C_RESET}"; }

# ------------------------------------------------------------------ préflight
[ "$(id -u)" -eq 0 ] || die "Ce script doit être exécuté en root (sudo bash $0)."

step "0/8 Détection de la plateforme"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  aarch64|arm64) PKG_ARCH="arm64" ;;
  armv7l|armhf)  PKG_ARCH="armhf" ;;
  x86_64|amd64)  PKG_ARCH="amd64" ;;
  *) die "Architecture non supportée : $ARCH_RAW" ;;
esac
OS_ID="$(. /etc/os-release && echo "${ID:-unknown}")"
OS_VER="$(. /etc/os-release && echo "${VERSION_ID:-unknown}")"
PI_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
[ -n "$PI_IP" ] || PI_IP="127.0.0.1"
HOST_FQDN="$(hostname)"
ok "Arch=${PKG_ARCH} (${ARCH_RAW}) | OS=${OS_ID} ${OS_VER} | IP=${PI_IP} | Host=${HOST_FQDN}"
export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------ paquets de base
step "1/8 Installation des prérequis"
apt-get update -qq
apt-get install -y -qq \
  ca-certificates curl wget gnupg apt-transport-https lsb-release \
  openssl dnsutils python3 procps >/dev/null
ok "Outils système installés"

# ------------------------------------------------------------------ libération du port 53
step "2/8 Libération du port 53 (systemd-resolved)"
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  if grep -q '^DNSStubListener=' /etc/systemd/resolved.conf 2>/dev/null; then
    sed -i 's/^DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
  else
    echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
  fi
  systemctl restart systemd-resolved || warn "Redémarrage de systemd-resolved impossible"
  # /etc/resolv.conf pointe souvent vers le stub 127.0.0.53 : le rediriger vers
  # le resolv.conf "uplink", sinon le Pi lui-même ne résout plus rien (apt…).
  if grep -q '127.0.0.53' /etc/resolv.conf 2>/dev/null; then
    if [ -e /run/systemd/resolve/resolv.conf ]; then
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    else
      printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
    fi
    ok "Stub 127.0.0.53:53 désactivé et /etc/resolv.conf redirigé vers l'uplink"
  else
    ok "Stub 127.0.0.53:53 désactivé"
  fi
else
  ok "systemd-resolved absent/inactif : rien à libérer"
fi
if ss -lntup 2>/dev/null | grep -qE ':53\s'; then
  warn "Le port 53 semble encore occupé : $(ss -lntup | grep -E ':53\s' | head -3)"
fi

# ------------------------------------------------------------------ UNBOUND
step "3/8 Installation et durcissement d'Unbound (backend 127.0.0.1:5353)"
apt-get install -y -qq unbound unbound-anchor >/dev/null || apt-get install -y -qq unbound >/dev/null
install -d -o unbound -g unbound -m 755 /var/lib/unbound
install -d -o root   -g unbound -m 750 /etc/unbound/blocklists

# Ancre de confiance DNSSEC (RFC 5011)
if [ ! -s /var/lib/unbound/root.key ]; then
  if command -v unbound-anchor >/dev/null 2>&1; then
    unbound-anchor -a /var/lib/unbound/root.key || warn "Ancre racine non téléchargée (vérifier la connectivité)"
  else
    warn "unbound-anchor absent : DNSSEC risque d'échouer au 1er démarrage"
  fi
fi
[ -e /var/lib/unbound/root.key ] && chown unbound:unbound /var/lib/unbound/root.key

cat > /etc/unbound/blocklists/threats.conf <<'EOF'
# Configuration de blocage préventif (Sinkhole Threat Intelligence)
# Les requêtes vers ces domaines renvoient immédiatement 0.0.0.0 ou ::

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

cat > /etc/unbound/unbound.conf <<'EOF'
# =====================================================================
# Unbound — moteur récursif durci (profil DNSaton)
# Écoute sur 127.0.0.1:5353 : inaccessible depuis le réseau.
# DNSdist est le SEUL client autorisé (équivalent du bridge Docker).
# =====================================================================
server:
    # --- Identité / environnement (valeurs Debian/Raspbian) ---
    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""
    pidfile: "/run/unbound.pid"

    # --- 1. Écoute réseau & Concurrence ---
    verbosity: 1
    interface: 127.0.0.1
    port: 5353
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    num-threads: 2

    # --- 2. Contrôle d'accès (isolation stricte) ---
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow

    # --- 3. Intégrité / Authenticité : DNSSEC ---
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no

    # --- 4. Vie privée ---
    qname-minimisation: yes
    hide-identity: yes
    hide-version: yes

    # --- 5. Anti-empoisonnement de cache ---
    use-caps-for-id: yes
    outgoing-range: 8192
    outgoing-num-tcp: 128
    incoming-num-tcp: 128

    # --- 6. Anti-fragmentation (DNS Flag Day) ---
    edns-buffer-size: 1232
    max-udp-size: 1232

    # --- 7. Cache ---
    msg-cache-size: 64m
    rrset-cache-size: 128m
    infra-cache-numhosts: 10000
    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes

    # --- 8. Threat Intelligence ---
    include: "/etc/unbound/blocklists/*.conf"
EOF
unbound-checkconf /etc/unbound/unbound.conf || die "Configuration Unbound invalide"
systemctl enable unbound >/dev/null 2>&1
systemctl restart unbound
ok "Unbound actif sur 127.0.0.1:5353 (DNSSEC + sinkhole)"

# ------------------------------------------------------------------ CERTIFICATS
step "4/8 Génération des certificats TLS (DoH / DoT)"
install -d -m 755 /etc/dnsdist/certs
if [ ! -s /etc/dnsdist/certs/server.crt ] || [ ! -s /etc/dnsdist/certs/server.key ]; then
  SAN="DNS:localhost,DNS:${HOST_FQDN},DNS:dnsaton.local,IP:127.0.0.1"
  case "$PI_IP" in
    127.0.0.1) : ;;
    *) SAN="${SAN},IP:${PI_IP}" ;;
  esac
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/dnsdist/certs/server.key \
    -out    /etc/dnsdist/certs/server.crt \
    -subj "/CN=dnsaton.local/O=Hackathon DNS Resolver/C=FR" \
    -addext "subjectAltName=${SAN}" >/dev/null 2>&1
  ok "Certificat généré (SAN: ${SAN})"
else
  ok "Certificat existant conservé"
fi
[ ! -s /etc/dnsdist/certs/dnsdist-api.env ] && \
  echo "API_KEY=$(openssl rand -hex 16)" > /etc/dnsdist/certs/dnsdist-api.env
chmod 644 /etc/dnsdist/certs/server.crt

# Le key doit être lisible par l'utilisateur du service dnsdist (_dnsdist sur Debian)
DNSDIST_USER="$(systemctl cat dnsdist.service 2>/dev/null | grep -m1 -oE '^User=\S+' | cut -d= -f2 || true)"
[ -n "$DNSDIST_USER" ] || DNSDIST_USER="_dnsdist"
if id "$DNSDIST_USER" >/dev/null 2>&1; then
  chown "root:${DNSDIST_USER}" /etc/dnsdist/certs/server.key
  chmod 640 /etc/dnsdist/certs/server.key
else
  chmod 644 /etc/dnsdist/certs/server.key
  warn "Utilisateur $DNSDIST_USER introuvable : clé en 644"
fi

# ------------------------------------------------------------------ DNSDIST
step "5/8 Installation de DNSdist (frontend 53/853/443/8083)"
apt-get install -y -qq dnsdist >/dev/null
install -d -m 755 /etc/dnsdist

cat > /etc/dnsdist/dnsdist.conf <<'EOF'
-- ====================================================================
-- DNSdist Configuration - Passerelle Sécurisée & Anti-DDoS (DNSaton)
-- Version native Raspberry Pi : backend = 127.0.0.1:5353 (Unbound local)
-- ====================================================================

-- 1. Interfaces d'écoute
setLocal("0.0.0.0:53", { reusePort=true })
addTLSLocal("0.0.0.0:853", "/etc/dnsdist/certs/server.crt", "/etc/dnsdist/certs/server.key")
addDOHLocal("0.0.0.0:443", "/etc/dnsdist/certs/server.crt", "/etc/dnsdist/certs/server.key", {"/dns-query"}, { reusePort=true })

-- Résolveur public : autoriser les requêtes de tous les réseaux
addACL("0.0.0.0/0")
addACL("::/0")

-- 2. Console Web & Métriques Prometheus
webserver("0.0.0.0:8083")
setWebserverConfig({password="hackathon2026", apiKey="hackathon2026", statsRequireAuthentication=false, acl="0.0.0.0/0, ::/0"})

-- 3. Backend récursif (Unbound, isolé en boucle locale)
newServer({
    address="127.0.0.1:5353",
    name="unbound-backend",
    checkInterval=2,
    checkTimeout=1000,
    maxCheckFailures=3,
    mustResolve=false
})

-- 4. Anti-DDoS & durcissement
addAction(QTypeRule(DNSQType.ANY), DropAction())
addAction(MaxQPSIPRule(50, 32, 64), DelayAction(100))
addAction(MaxQPSIPRule(150, 32, 64), DropAction())

local dbr = dynBlockRulesGroup()
dbr:setQueryRate(100, 10, "Exceeded query rate limit", 60)
dbr:setRCodeRate(DNSRCode.SERVFAIL, 20, 10, "Exceeded SERVFAIL rate limit", 60)

function maintenance()
    dbr:apply()
end
EOF
chmod 644 /etc/dnsdist/dnsdist.conf
systemctl enable dnsdist >/dev/null 2>&1
systemctl restart dnsdist
ok "DNSdist actif (53 UDP/TCP, 853 DoT, 443 DoH, 8083 métriques)"

# ------------------------------------------------------------------ PROMETHEUS
step "6/8 Installation de Prometheus (127.0.0.1:9090)"
apt-get install -y -qq prometheus >/dev/null
install -d -o prometheus -g prometheus -m 755 /var/lib/prometheus
cat > /etc/prometheus/prometheus.yml <<'EOF'
global:
  scrape_interval: 2s
  evaluation_interval: 2s

scrape_configs:
  - job_name: "dnsdist"
    static_configs:
      - targets: ["127.0.0.1:8083"]
EOF
chown root:prometheus /etc/prometheus/prometheus.yml
chmod 640 /etc/prometheus/prometheus.yml
systemctl enable prometheus >/dev/null 2>&1
systemctl restart prometheus
ok "Prometheus actif (scrape dnsdist toutes les 2s)"

# ------------------------------------------------------------------ GRAFANA
step "7/8 Installation de Grafana (3000) et provisioning"
if ! command -v grafana-server >/dev/null 2>&1; then
  curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana.gpg
  echo "deb [signed-by=/usr/share/keyrings/grafana.gpg arch=${PKG_ARCH}] https://packages.grafana.com/oss/deb stable main" \
    > /etc/apt/sources.list.d/grafana.list
  apt-get update -qq
  apt-get install -y -qq grafana >/dev/null
fi

install -d -m 755 /etc/grafana/provisioning/datasources \
                  /etc/grafana/provisioning/dashboards \
                  /var/lib/grafana/dashboards

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

cat > /var/lib/grafana/dashboards/dns-overview.json <<'EOF'
{
  "annotations": { "list": [] },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "liveNow": true,
  "panels": [
    {
      "collapsed": false,
      "gridPos": { "h": 4, "w": 6, "x": 0, "y": 0 },
      "id": 1,
      "title": "Total Requêtes DNS",
      "type": "stat",
      "targets": [ { "expr": "dnsdist_queries", "refId": "A" } ],
      "fieldConfig": {
        "defaults": { "color": { "mode": "palette-classic" }, "unit": "short" }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 4, "w": 6, "x": 6, "y": 0 },
      "id": 2,
      "title": "Requêtes Bloquées / Dropped",
      "type": "stat",
      "targets": [ { "expr": "dnsdist_rule_drop", "refId": "A" } ],
      "fieldConfig": {
        "defaults": { "color": { "fixedColor": "red", "mode": "fixed" }, "unit": "short" }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 4, "w": 6, "x": 12, "y": 0 },
      "id": 3,
      "title": "Requêtes DoH (HTTPS:443)",
      "type": "stat",
      "targets": [ { "expr": "dnsdist_doh_queries", "refId": "A" } ],
      "fieldConfig": {
        "defaults": { "color": { "fixedColor": "green", "mode": "fixed" }, "unit": "short" }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 4, "w": 6, "x": 18, "y": 0 },
      "id": 4,
      "title": "Requêtes DoT (TLS:853)",
      "type": "stat",
      "targets": [ { "expr": "dnsdist_tls_queries", "refId": "A" } ],
      "fieldConfig": {
        "defaults": { "color": { "fixedColor": "blue", "mode": "fixed" }, "unit": "short" }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 4 },
      "id": 5,
      "title": "Débit de requêtes en direct (QPS - Queries/sec)",
      "type": "timeseries",
      "targets": [
        { "expr": "rate(dnsdist_queries[10s])", "legendFormat": "Toutes les requêtes (QPS)", "refId": "A" },
        { "expr": "rate(dnsdist_doh_queries[10s])", "legendFormat": "DoH (HTTPS)", "refId": "B" },
        { "expr": "rate(dnsdist_tls_queries[10s])", "legendFormat": "DoT (TLS)", "refId": "C" }
      ],
      "fieldConfig": {
        "defaults": { "custom": { "fillOpacity": 15, "lineWidth": 2 }, "unit": "reqps" }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 4 },
      "id": 6,
      "title": "Attaques Bloquées & Bridation (Drops / Amplification)",
      "type": "timeseries",
      "targets": [
        { "expr": "rate(dnsdist_rule_drop[10s])", "legendFormat": "Attaques bloquées (Drops/sec)", "refId": "A" },
        { "expr": "rate(dnsdist_dyn_blocked[10s])", "legendFormat": "IPs bannies dynamiquement", "refId": "B" }
      ],
      "fieldConfig": {
        "defaults": { "color": { "fixedColor": "red", "mode": "fixed" }, "custom": { "fillOpacity": 30, "lineWidth": 2 }, "unit": "reqps" }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 12 },
      "id": 7,
      "title": "Latence moyenne de résolution backend (ms)",
      "type": "timeseries",
      "targets": [
        { "expr": "dnsdist_latency_avg_100 / 1000", "legendFormat": "Latence moyenne (ms)", "refId": "A" }
      ],
      "fieldConfig": {
        "defaults": { "unit": "ms", "custom": { "fillOpacity": 10, "lineWidth": 2 } }
      }
    },
    {
      "collapsed": false,
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 12 },
      "id": 8,
      "title": "État de santé du Backend Unbound",
      "type": "stat",
      "targets": [ { "expr": "dnsdist_servers_up", "refId": "A" } ],
      "fieldConfig": {
        "defaults": {
          "mappings": [
            { "type": "value", "options": { "1": { "text": "OPÉRATIONNEL (UP)", "color": "green" }, "0": { "text": "PANNE (DOWN)", "color": "red" } } }
          ]
        }
      }
    }
  ],
  "refresh": "2s",
  "schemaVersion": 38,
  "style": "dark",
  "tags": ["dns", "dnsdist", "hackathon"],
  "time": { "from": "now-5m", "to": "now" },
  "timepicker": { "refresh_intervals": ["2s", "5s", "10s"] },
  "timezone": "browser",
  "title": "DNSaton - Supervision Sécurité & Trafic",
  "uid": "dnsaton-overview",
  "version": 1
}
EOF
chown -R grafana:grafana /var/lib/grafana/dashboards

# Reproduit les variables d'environnement du conteneur Grafana
install -d -m 755 /etc/systemd/system/grafana-server.service.d
cat > /etc/systemd/system/grafana-server.service.d/dnsaton.conf <<'EOF'
[Service]
Environment="GF_SECURITY_ADMIN_USER=admin"
Environment="GF_SECURITY_ADMIN_PASSWORD=admin"
Environment="GF_USERS_ALLOW_SIGN_UP=false"
Environment="GF_AUTH_ANONYMOUS_ENABLED=true"
Environment="GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer"
EOF
systemctl daemon-reload
systemctl enable grafana-server >/dev/null 2>&1
systemctl restart grafana-server
ok "Grafana actif avec dashboard dnsaton-overview préchargé"

# ------------------------------------------------------------------ VALIDATION
step "8/8 Validation finale"
sleep 3
for svc in unbound dnsdist prometheus grafana-server; do
  state="$(systemctl is-active "$svc" 2>/dev/null || echo 'inconnu')"
  if [ "$state" = "active" ]; then ok "$svc : active"; else warn "$svc : $state"; fi
done

echo ""
info "Test de résolution DNS classique :"
dig @127.0.0.1 example.com +short +time=3 | head -2 || true

info "Test du sinkhole malware :"
dig @127.0.0.1 malware-test.evil.local +short || true

info "Métriques DNSdist :"
curl -s http://127.0.0.1:8083/metrics | grep -c '^dnsdist_' || true

echo ""
echo -e "${C_CYAN}==============================================================================${C_RESET}"
echo -e "${C_GREEN}  DNSATON DÉPLOYÉ NATIVEMENT SUR RASPBERRY PI (sans Docker)${C_RESET}"
echo -e "${C_CYAN}==============================================================================${C_RESET}"
printf "  Résolveur public      : UDP/TCP 53 sur %s\n" "$PI_IP"
printf "  DoT                   : tls://%s:853\n" "$PI_IP"
printf "  DoH                   : https://%s/dns-query\n" "$PI_IP"
printf "  Backend Unbound       : 127.0.0.1:5353 (loopback uniquement)\n"
printf "  Métriques             : http://%s:8083/metrics\n" "$PI_IP"
printf "  Prometheus            : http://%s:9090\n" "$PI_IP"
printf "  Grafana (admin/admin) : http://%s:3000/d/dnsaton-overview\n" "$PI_IP"
echo -e "${C_CYAN}==============================================================================${C_RESET}"
echo -e "${C_YELLOW}  Note : certificat auto-signé -> ajouter l'exception sur les clients DoH/DoT.${C_RESET}"
echo -e "${C_YELLOW}  Pour régénérer le certificat : supprimer /etc/dnsdist/certs/server.* puis relancer.${C_RESET}"
