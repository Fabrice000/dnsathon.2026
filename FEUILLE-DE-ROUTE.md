# Feuille de route — Sécurisation du résolveur DNS

> **Exercice d'entraînement (blue team).** Vous reprenez un résolveur DNS « monté à la hâte » :
> il fonctionne, mais il a été déployé sans durcissement. Votre mission : **identifier ses
> faiblesses, les corriger, et le prouver par des tests avant/après.**

> ⚠️ **Cadre.** Ce résolveur est une cible de **lab isolé**. Ne l'exposez jamais sur l'Internet
> public tel quel : un résolveur ouvert est détourné pour des attaques par amplification. Tous
> les tests d'abus restent **dans le réseau du lab**, vers votre propre résolveur.

## 1. Mise en route

```bash
./scripts/generate-certs.sh    # génère vos propres certificats + secrets (hors Git)
docker compose up -d
docker compose ps              # les 4 conteneurs doivent être "Up"
dig @127.0.0.1 example.com +short   # le résolveur répond : la cible est vivante
```

Architecture : **DNSdist** (frontend, ports 53/853/443) → **Unbound** (récursif) → Internet.
Supervision : **Prometheus** + **Grafana** (`http://localhost:3000`).

## 2. Objectifs notés

| # | Objectif | Question à vous poser |
| :-- | :-- | :-- |
| 1 | **Réponses légitimes** | N'importe qui sur le réseau peut-il obtenir une réponse ? Qui *devrait* pouvoir ? |
| 2 | **DNSSEC** | Un domaine à signature **invalide** est-il bien rejeté, ou passe-t-il quand même ? |
| 3 | **Rate limiting** | Que se passe-t-il si une IP envoie des milliers de requêtes par seconde ? |
| 4 | **Journaux d'abus** | Après une attaque simulée, retrouvez-vous la trace du coupable dans les logs ? |

## 3. Zones à auditer

Parcourez ces fichiers et confrontez-les aux objectifs ci-dessus. Tout n'est pas forcément à
changer — à vous de juger ce qui est sûr et ce qui ne l'est pas.

- `dnsdist/dnsdist.conf` — qui est autorisé (`addACL`) ? quelles règles protègent contre les
  floods et l'amplification (requêtes `ANY`) ? la console de métriques est-elle protégée ?
- `unbound/unbound.conf` — la validation DNSSEC est-elle **stricte** ? la journalisation des
  requêtes est-elle active ? le moteur récursif est-il bien isolé derrière le frontend ?
- `docker-compose.yml` — quels ports d'administration sont exposés, et à qui ? les mots de
  passe par défaut ont-ils été changés ?
- `certs/` & secrets — des identifiants sont-ils écrits en clair dans un fichier versionné ?

## 4. Méthode de test (avant / après)

```bash
# Résolveur ouvert : une IP "extérieure" obtient-elle une réponse ?
dig @<ip_resolveur> example.com            # (depuis une machine NON autorisée du lab)

# DNSSEC : le domaine volontairement cassé doit renvoyer SERVFAIL
dig @<ip_resolveur> dnssec-failed.org
dig @<ip_resolveur> cloudflare.com +dnssec  # doit porter le flag "ad"

# Amplification : une petite requête ANY produit-elle une grosse réponse ?
dig @<ip_resolveur> isc.org ANY +bufsize=4096 | grep "MSG SIZE"

# Charge : taux de requêtes traité / perdu (depuis la machine de test UNIQUEMENT)
dnsperf -s <ip_resolveur> -d requetes.txt -l 30 -Q 5000

# Journaux : l'abus est-il visible ?
docker compose logs -f unbound
docker compose logs -f dnsdist
```

Remplissez un tableau **avant / après** pour chaque objectif : c'est la preuve attendue au jury.

## 5. Barème

Chaque objectif de la section 2 corrigé **et démontré** (test avant/après + justification écrite)
compte pour la note. Bonne chasse. 🔍
