# DAT PPHOOK - Document d'Architecture Technique

**Version:** 1.0  
**Date:** Janvier 2025  
**Auteur:** Stagiaire n°38
**Projet:** PPHOOK - phpIPAM/PowerDNS Hook - Integration Middleware

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-GPL%20v3.0-green)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen)

---

## Table des Matières

1. [Présentation du Projet](#1-présentation-du-projet)
2. [Analyse de l'Existant](#2-analyse-de-lexistant)
3. [Architecture Générale](#3-architecture-générale)
4. [Architecture Technique Détaillée](#4-architecture-technique-détaillée)
5. [Architecture Réseau et Sécurité](#5-architecture-réseau-et-sécurité)
6. [Processus Métier et Algorithmes](#6-processus-métier-et-algorithmes)
7. [Interface Utilisateur et Monitoring](#7-interface-utilisateur-et-monitoring)
8. [Déploiement et Exploitation](#8-déploiement-et-exploitation)
9. [Performance et Scalabilité](#9-performance-et-scalabilité)

---

## 1. Présentation du Projet

### 1.1 Contexte et enjeux

Ce projet s'inscrit dans une infrastructure d'intégration phpIPAM/PowerDNS, où phpIPAM gère l'inventaire des adresses IP du réseau et PowerDNS est le serveur DNS maître du réseau. Lors des saisies d'informations dans phpIPAM, il n'y a aucune vérification qui est faite sur la cohérence et la validité des entrées.

Cette absence de contrôle génère de nombreuses problématiques opérationnelles qui impactent directement la qualité du service réseau et la productivité des équipes d'administration.

**Problématiques identifiées :**
- **Incohérences DNS** : Enregistrements DNS orphelins (A records sans PTR correspondants) créant des dysfonctionnements de résolution
- **Doublons critiques** : Adresses MAC dupliquées dans les réservations DHCP provoquant des conflits réseau
- **Conflits de nommage** : Hostnames identiques sur différentes adresses IP générant des confusions
- **Validation insuffisante** : Absence de validation des zones DNS lors de la création d'entrées
- **Processus manuels** : Synchronisation manuelle chronophage et source d'erreurs humaines
- **Audit inexistant** : Pas de traçabilité des modifications et corrections effectuées

**Enjeux business :**
- Amélioration de la fiabilité du service réseau
- Réduction du temps d'intervention des équipes techniques
- Minimisation des interruptions de service liées aux erreurs DNS
- Standardisation des processus de gestion des adresses IP

### 1.2 Objectifs du projet

**Objectif principal :** Développer une solution logicielle qui permet de vérifier, corriger et alerter les utilisateurs sur les erreurs saisies dans phpIPAM, tout en assurant la synchronisation automatique avec PowerDNS.

**Objectifs spécifiques :**
- **Validation automatique** : Contrôler la cohérence des données saisies selon les standards DNS (RFC 1035)
- **Synchronisation intelligente** : Automatiser la synchronisation bidirectionnelle entre phpIPAM et PowerDNS
- **Détection proactive** : Identifier automatiquement les doublons MAC et hostname avant qu'ils ne causent des dysfonctionnements
- **Correction automatique** : Résoudre automatiquement les conflits selon des règles métier prédéfinies
- **Notification ciblée** : Alerter les utilisateurs responsables des erreurs avec des informations précises pour correction
- **Audit complet** : Maintenir un historique détaillé de toutes les opérations pour conformité et diagnostic
- **Génération automatique** : Produire automatiquement les configurations DHCP et DNS à partir des données validées

### 1.3 Périmètre fonctionnel

**Périmètre inclus :**

*Fonctionnalités principales :*
- **Synchronisation temps réel** : Traitement automatique des modifications phpIPAM vers PowerDNS
- **Validation DNS complète** : Vérification conformité RFC 1035 et cohérence des zones
- **Gestion des doublons** : Détection et résolution automatique des conflits MAC/hostname
- **Système de notifications** : Alertes email personnalisées avec templates dynamiques
- **Génération de configurations** : Production automatique des fichiers DHCP et BIND
- **Monitoring AXFR** : Surveillance temps réel des transferts de zones DNS
- **Protection anti-surcharge** : Limitation du traitement pour éviter les impacts système
- **Audit trail** : Traçabilité complète des opérations et modifications

*Données traitées :*
- Adresses IP et noms d'hôtes
- Adresses MAC et profils DHCP
- Enregistrements DNS (A, PTR)
- Zones DNS et configurations
- Informations utilisateur et changelog

**Périmètre exclu :**
- Modification directe des configurations réseau actives
- Gestion des utilisateurs et permissions phpIPAM/PowerDNS
- Sauvegarde et restauration des bases de données
- Interface graphique web dédiée (utilisation logs et monitoring système)
- Gestion des certificats SSL/TLS
- Configuration initiale des zones DNS (doit être préalable)

### 1.4 Contraintes et hypothèses

**Contraintes techniques :**
- **Compatibilité logicielle** : phpIPAM 1.7+ et PowerDNS 4.7+ minimum requis
- **Environnement système** : Déploiement exclusivement sur Debian 11+ / Ubuntu 20.04+
- **Ressources matérielles** : Minimum 4GB RAM et 10GB espace disque pour le serveur PPHOOK
- **Connectivité réseau** : Accès HTTP/HTTPS aux APIs phpIPAM et PowerDNS obligatoire
- **Base de données** : MySQL/MariaDB 5.7+ avec accès concurrent aux bases phpIPAM et PowerDNS
- **Sécurité** : Chiffrement GPG des configurations et gestion sécurisée des credentials
- **Performance** : Temps de traitement maximal de 60 secondes par cycle de synchronisation

**Contraintes opérationnelles :**
- **Disponibilité** : Service 24/7 avec tolérance aux pannes temporaires des APIs
- **Notifications** : Serveur SMTP accessible pour envoi d'alertes
- **Maintenance** : Fenêtres de maintenance coordonnées avec les services dépendants
- **Audit** : Conservation des logs pendant minimum 6 mois pour conformité

**Hypothèses de fonctionnement :**
- **Services opérationnels** : phpIPAM et PowerDNS fonctionnels et correctement configurés
- **APIs accessibles** : Endpoints REST disponibles avec authentification valide
- **Zones DNS existantes** : Zones forward et reverse préalablement créées dans PowerDNS
- **Utilisateurs configurés** : Comptes utilisateur phpIPAM avec adresses email valides
- **Réseau stable** : Connectivité réseau fiable entre tous les composants
- **Données initiales** : Base de données phpIPAM contenant des données cohérentes au démarrage

**Hypothèses métier :**
- **Règles de résolution** : En cas de doublon, conservation de l'entrée la plus ancienne
- **Notifications acceptées** : Utilisateurs acceptent de recevoir des alertes automatiques
- **Zones DNS définies** : Périmètre des zones DNS géré connu et stable
- **Profils DHCP** : Utilisation des profils "infra" et "lise" pour les réservations

---

## 2. Analyse de l'Existant

### 2.1 Infrastructure actuelle

**Composants existants :**
- phpIPAM : Gestion centralisée des adresses IP et inventaire réseau
- PowerDNS : Serveur DNS autoritaire avec API REST
- Serveurs BIND9 : Serveurs DNS esclaves pour la distribution
- Serveur DHCP : Distribution automatique des adresses IP
- Base de données MySQL/MariaDB : Stockage des données phpIPAM et PowerDNS

![Infrastructure Actuelle](./images/infra_existant.png "Schéma Infrastructure Actuelle")

### 2.2 Problématiques identifiées

**Incohérences DNS :**
- Enregistrements A sans PTR correspondants
- Adresses IP dans phpIPAM sans enregistrements DNS
- Enregistrements DNS orphelins après suppression dans phpIPAM
- Zones DNS non validées lors de la création d'entries

**Doublons et conflicts :**
- Adresses MAC dupliquées dans les réservations DHCP
- Noms d'hôtes identiques sur différentes adresses IP
- Conflits de noms lors de la génération des configurations

**Processus manuels :**
- Synchronisation manuelle entre phpIPAM et PowerDNS
- Génération manuelle des configurations DHCP
- Vérification manuelle de la cohérence des données
- Résolution manuelle des conflits

### 2.3 Solutions envisagées

**Option 1 : Script Entre-deux**
- Avantages : Contrôle total
- Inconvénients : Perte d'intégration native PowerDNS > phpIPAM 

**Option 2 : Middleware temps réel (solution retenue)**
- Avantages : Synchronisation continue, validation automatique, notifications
- Inconvénients : Complexité plus élevée, maintenance

**Option 3 : Intégration directe dans phpIPAM**
- Avantages : Intégration native
- Inconvénients : Modification du code source, dépendance aux mises à jour

### 2.4 Justification de l'approche retenue

L'approche middleware a été retenue pour ses avantages :
- **Indépendance** : Pas de modification des systèmes existants
- **Flexibilité** : Possibilité d'adaptation aux évolutions
- **Maintenabilité** : Code centralisé et spécialisé
- **Monitoring** : Surveillance dédiée des processus
- **Évolutivité** : Ajout facile de nouvelles fonctionnalités

---

## 3. Architecture Générale

### 3.1 Vue d'ensemble du système

PPHOOK agit comme un middleware intelligent entre phpIPAM et PowerDNS, assurant la cohérence des données DNS et la génération automatique des configurations réseau.

![Process PPHOOK](./images/pphook_process.png "Schéma du Process")

### 3.2 Composants principaux

**PPHOOK Core :**
- **hook.py** : Orchestrateur principal et logique métier
- **phpipam.py** : Interface API phpIPAM
- **pdns.py** : Interface API PowerDNS
- **Service système** : Démon de synchronisation continue

**Modules utilitaires :**
- **dhcpd_conf_gen.py** : Génération configurations DHCP
- **bind_local_gen.py** : Génération configurations BIND
- **Scripts de monitoring** : Surveillance AXFR et santé système

**Infrastructure :**
- **Base de données** : MySQL/MariaDB pour phpIPAM et PowerDNS
- **Configuration chiffrée** : Stockage sécurisé des credentials
- **Logging centralisé** : Audit trail complet

### 3.3 Flux de données

**Flux principal de synchronisation :**
1. Récupération des modifications depuis phpIPAM
2. Validation des données (IP, hostname, zones DNS)
3. Détection et résolution des doublons
4. Synchronisation avec PowerDNS
5. Génération des configurations DHCP/DNS
6. Notification des administrateurs

**Flux de données bidirectionnel :**
- phpIPAM → PPHOOK → PowerDNS (création/modification)
- PowerDNS → PPHOOK → phpIPAM (validation/nettoyage)

### 3.4 Interfaces et intégrations

**APIs utilisées :**
- phpIPAM REST API : Récupération des adresses et changelog
- PowerDNS API : Gestion des enregistrements DNS
- SMTP : Notifications email
- Système de fichiers : Configurations générées

**Protocoles réseau :**
- HTTP/HTTPS pour les APIs
- SMTP pour les notifications
- SSH/SCP pour le déploiement des configurations
- DNS (TCP/UDP 53) pour la validation

---

## 4. Architecture Technique Détaillée

### 4.1 Composant PPHOOK (Middleware)

**Structure modulaire :**

```
/opt/pphook/
├── hook.py              # Orchestrateur principal
├── phpipam.py           # Module API phpIPAM
├── pdns.py              # Module API PowerDNS
├── config.ini           # Configuration système
├── templates/           # Templates email et configs
├── pphook_venv/         # Environnement virtuel Python
```

**Fonctionnalités du hook.py :**
- Orchestration des processus de synchronisation
- Gestion des timestamps et protection contre les traitements massifs
- Validation des données selon RFC 1035
- Gestion des erreurs et notifications
- Audit trail complet

**Classe PhpIPAMAPI :**
- Authentification et gestion des tokens
- Récupération des adresses modifiées
- Détection des doublons MAC et hostname
- Gestion du changelog et des utilisateurs

**Classe PowerDNSAPI :**
- Gestion des enregistrements DNS A et PTR
- Validation des zones DNS
- Nettoyage des enregistrements orphelins
- Optimisations avec cache DNS

### 4.2 Intégration phpIPAM

**API REST phpIPAM :**
- Endpoint : `/api/{app_id}/addresses/`
- Authentification : Token-based
- Filtrage par date de modification
- Récupération du changelog des adresses

**Données traitées :**
- Adresses IP et hostnames
- Adresses MAC et profils DHCP
- Timestamps de modification
- Informations utilisateur

**Gestion des doublons :**
- Algorithme de détection des doublons MAC
- Résolution des conflits hostname
- Conservation de l'adresse la plus ancienne
- Notification des utilisateurs concernés

### 4.3 Intégration PowerDNS

**API REST PowerDNS :**
- Endpoint : `/api/v1/servers/{server}/zones/`
- Authentification : API Key
- Gestion des enregistrements A et PTR
- Validation des zones DNS

**Opérations DNS :**
- Création/modification d'enregistrements A
- Gestion des enregistrements PTR (reverse DNS)
- Validation de la cohérence A ↔ PTR
- Nettoyage des enregistrements orphelins

**Optimisations :**
- Cache des zones DNS (TTL 1 heure)
- Sessions HTTP persistantes
- Retry automatique en cas d'erreur
- Validation locale avant requêtage API

### 4.4 Base de données

**Bases de données utilisées :**
- `phpipam` : Stockage des adresses IP et inventaire
- `powerdns` : Enregistrements DNS et zones
- `pdnsadmin` : Interface d'administration PowerDNS (optionnel)

**Utilisateurs et permissions :**
- `ipam_user` : Accès lecture/écriture phpIPAM et lecture PowerDNS
- `pdns_user` : Accès complet base PowerDNS
- `pdnsadmin_user` : Accès interface d'administration

**Optimisations :**
- Index sur les colonnes de recherche fréquente
- Connexions TCP optimisées
- Gestion des timeouts et reconnexions

---

## 5. Architecture Réseau et Sécurité

### 5.1 Topologie réseau

[SCHEMA DE LA TOPOLOGIE RESEAU]

**Serveurs principaux :**
- Serveur PPHOOK : [informations à compléter - IP de gestion]
- Serveur phpIPAM : [informations à compléter - IP de gestion]
- Serveur PowerDNS : [informations à compléter - IP de gestion]
- Serveur Base de données : [informations à compléter - IP de gestion]
- Serveurs DNS esclaves : [informations à compléter - IPs NS01 et NS02]

### 5.2 Flux réseau et ports

**Ports utilisés :**
- TCP 80/443 : API phpIPAM
- TCP 8081 : API PowerDNS
- TCP 3306 : Base de données MySQL
- TCP 25 : SMTP notifications
- TCP 22 : SSH déploiement configs
- TCP/UDP 53 : DNS queries/AXFR

**Flux réseau :**
- PPHOOK → phpIPAM : HTTP/HTTPS (port 80/443)
- PPHOOK → PowerDNS : HTTP (port 8081)
- PPHOOK → Base de données : MySQL (port 3306)
- PPHOOK → SMTP : SMTP (port 25)
- PPHOOK → DNS slaves : SSH (port 22)

### 5.3 Sécurisation des communications

**Chiffrement des communications :**
- HTTPS pour phpIPAM si disponible
- API PowerDNS avec clé d'authentification
- Connexions base de données chiffrées
- SSH pour déploiement configurations

**Authentification :**
- Tokens d'authentification phpIPAM
- Clés API PowerDNS
- Credentials base de données chiffrés
- Clés SSH pour déploiement

### 5.4 Gestion des accès et authentification

**Principes de sécurité :**
- Moindre privilège pour chaque service
- Authentification forte pour tous les accès
- Audit trail complet des opérations
- Rotation régulière des credentials

**Comptes de service :**
- Compte dédié PPHOOK avec permissions minimales
- Comptes utilisateurs séparés pour DHCP et BIND
- Pas d'accès root direct aux services

### 5.5 Chiffrement des configurations

**Gestion des secrets :**
- Chiffrement GPG des fichiers de configuration
- Passphrase stockée séparément
- Variables d'environnement sécurisées
- Aucun credential en clair dans le code

**Implémentation :**
```bash
# Chiffrement configuration
gpg --symmetric --cipher-algo AES256 --output .env.gpg .env

# Déchiffrement runtime
gpg --batch --passphrase-file .gpg_passphrase --quiet --decrypt .env.gpg
```

---

## 6. Processus Métier et Algorithmes

### 6.1 Cycle de synchronisation

**Cycle principal (60 secondes) :**
1. **Récupération des modifications** : Query phpIPAM pour les adresses modifiées
2. **Validation des données** : Vérification IP, hostname, zones DNS
3. **Détection des doublons** : Algorithmes de détection MAC/hostname
4. **Résolution des conflits** : Suppression/correction automatique
5. **Synchronisation DNS** : Création/modification enregistrements PowerDNS
6. **Génération configs** : Mise à jour DHCP et BIND si nécessaire
7. **Notifications** : Alertes administrateurs si erreurs

**Protection contre les traitements massifs :**
- Limitation à 7 jours de données historiques
- Fichier bypass pour traitements exceptionnels
- Validation des timestamps avant traitement

### 6.2 Algorithmes de détection des doublons

**Détection doublons MAC :**
```python
def find_mac_duplicates(addresses):
    mac_groups = {}
    for addr in addresses:
        mac = addr.get('mac')
        if mac:
            if mac not in mac_groups:
                mac_groups[mac] = []
            mac_groups[mac].append(addr)
    
    return {mac: addrs for mac, addrs in mac_groups.items() if len(addrs) > 1}
```

**Détection doublons hostname :**
```python
def find_hostname_duplicates(addresses):
    hostname_groups = {}
    for addr in addresses:
        hostname = addr.get('hostname')
        if hostname:
            hostname_clean = hostname.lower().strip()
            if hostname_clean not in hostname_groups:
                hostname_groups[hostname_clean] = []
            hostname_groups[hostname_clean].append(addr)
    
    return {hostname: addrs for hostname, addrs in hostname_groups.items() if len(addrs) > 1}
```

### 6.3 Logique de résolution des conflits

**Stratégie de résolution :**
1. **Identification de l'adresse à conserver** : Plus ancienne selon editDate puis ID
2. **Suppression des doublons** : Suppression MAC ou adresse complète
3. **Nettoyage DNS** : Suppression enregistrements orphelins
4. **Notification utilisateur** : Email détaillé avec liens phpIPAM

**Cas de traitement DNS :**
- **Cas 1 (no_records)** : Pas d'action (entrée inventaire)
- **Cas 2 (a_only)** : Création PTR si zone reverse existe
- **Cas 3 (ptr_only)** : Suppression PTR orphelin
- **Cas 4 (both_exist)** : Vérification cohérence A/PTR

### 6.4 Gestion des notifications

**Templates email :**
- `email_dns_error.j2` : Erreurs DNS génériques
- `email_mac_duplicate.j2` : Doublons MAC détectés
- `email_hostname_duplicate.j2` : Doublons hostname détectés

**Système de notification :**
- Email utilisateur récupéré depuis changelog phpIPAM
- Fallback sur email générique si utilisateur non trouvé
- Templates Jinja2 avec variables contextuelles
- Retry automatique en cas d'échec SMTP

### 6.5 Traitement des erreurs

**Catégories d'erreurs :**
- **Erreurs de validation** : Données invalides (IP, hostname)
- **Erreurs réseau** : Indisponibilité APIs
- **Erreurs DNS** : Zones inexistantes, enregistrements incohérents
- **Erreurs système** : Permissions, espace disque

**Stratégies de récupération :**
- Retry automatique avec backoff exponentiel
- Dégradation gracieuse en cas d'erreur partielle
- Logging détaillé pour diagnostic
- Notifications administrateur pour erreurs critiques

---

## 7. Interface Utilisateur et Monitoring

### 7.1 Système de logging

**Configuration logging :**
- Niveau INFO par défaut
- Sortie : fichier `/var/log/pphook.log`
- Rotation automatique des logs (logrotate)
- Format standardisé avec timestamp

**Informations loggées :**
- Début/fin de chaque cycle de synchronisation
- Détails des opérations DNS (création/suppression)
- Statistiques de performance (temps de traitement)
- Actions utilisateur (doublons résolus, notifications)

### 7.2 Métriques et indicateurs

**KPIs principaux :**
- Nombre d'adresses traitées par cycle
- Taux de succès des synchronisations DNS
- Nombre de doublons détectés/résolus
- Temps de réponse des APIs
- Taux d'erreurs par type

**Métriques techniques :**
- Temps de traitement par adresse
- Utilisation cache DNS
- Nombre d'appels API par service
- Statut des connexions réseau

### 7.3 Alertes et notifications

**Alertes système :**
- Échec d'authentification APIs
- Indisponibilité services critiques
- Erreurs de validation récurrentes
- Doublons massifs détectés

**Notifications utilisateur :**
- Email automatique pour doublons résolus
- Détails avec liens phpIPAM
- Information sur actions correctives
- Guidance pour éviter récidive

### 7.4 Tableaux de bord

**Monitoring AXFR :**
- Script `monitor_axfr.sh` vérifie synchronisation zones
- Comparaison serials master/slave
- Alertes en cas de désynchronisation
- Exécution cron toutes les 5 minutes

**Santé système :**
- Statut service PPHOOK
- Connectivité APIs phpIPAM/PowerDNS
- Statut base de données
- Espace disque et mémoire

### 7.5 Outils de diagnostic

**Scripts de diagnostic :**
- `reset_timestamp.sh` : Reset forcé timestamp
- Test connectivité APIs
- Validation configuration
- Vérification permissions

**Commandes utiles :**
```bash
# Statut service
systemctl status pphook

# Logs temps réel
tail -f /var/log/pphook.log

# Test APIs
curl -H "X-API-Key: $API_KEY" http://powerdns:8081/api/v1/servers
curl http://phpipam/api/app_id/sections/
```

---

## 8. Déploiement et Exploitation

### 8.1 Prérequis et environnement

**Système d'exploitation :**
- Debian 11+ ou Ubuntu 20.04+
- Minimum 4GB RAM
- 10GB espace disque libre
- Accès root/sudo

**Dépendances système :**
- Python 3.8+
- MySQL client
- GPG pour chiffrement
- SSH client
- Cron

**Réseau :**
- Connectivité HTTP vers phpIPAM et PowerDNS
- Accès MySQL vers base de données
- Accès SMTP pour notifications
- SSH vers serveurs DNS esclaves

### 8.2 Procédure d'installation

**Étape 1 : Préparation**
```bash
git clone < lien https git >
cd pphook
cp global_vars.sh.example global_vars.sh
# Éditer global_vars.sh avec vos paramètres
```

**Étape 2 : Configuration**
```bash
cd bash/
source create_env.sh
# Saisir passphrase GPG
```

**Étape 3 : Installation**
```bash
cd ../main_scripts/
source hook.sh
```

**Étape 4 : Vérification**
```bash
systemctl status pphook
tail -f /var/log/pphook.log
```

### 8.3 Exploitation et maintenance

**Opérations courantes :**
- Surveillance des logs
- Vérification synchronisation AXFR
- Mise à jour configurations
- Rotation des credentials

**Maintenance périodique :**
- Nettoyage logs anciens
- Vérification espace disque
- Test restauration configurations
- Mise à jour dépendances Python

**Procédures d'urgence :**
- Arrêt service en cas de problème
- Restauration configuration sauvegardée
- Bypass temporaire validations
- Notification équipe support

---

## 9. Performance et Scalabilité

### 9.1 Métriques de performance

**Métriques de performance :**

- Intervalle de synchronisation configuré modifiable : 60 secondes
- Logging des timestamps pour analyse manuelle
- Compteurs de succès/erreurs par cycle

**Métriques à implémenter :**

- Mesure temps de traitement par cycle
- Benchmark performance APIs
- Tests de charge avec volumétrie réelle
- Métriques de performance détaillées

### 9.2 Optimisations mises en œuvre

**Optimisations réseau :**
- Sessions HTTP persistantes
- Connexion pooling
- Retry automatique avec backoff
- Timeout configurables

**Optimisations données :**
- Cache DNS zones (TTL 1h)
- Filtrage par timestamp
- Traitement par batch
- Validation locale avant API

**Optimisations algorithmes :**
- Détection doublons O(n)
- Évitement re-traitement données
- Validation sélective
- Nettoyage ciblé

### 9.3 Capacité et dimensionnement

**Capacité actuelle :**

Aucune limite explicite implémentée dans le code
Traitement de toutes les adresses modifiées depuis le dernier cycle
Protection temporelle : données limitées à 7 jours d'historique

**Facteurs limitants potentiels :**

Performances des APIs externes phpIPAM/PowerDNS
Disponibilité et performances base de données
Ressources système (CPU, mémoire, réseau)

### 9.4 Évolutivité du système

**Scalabilité verticale :**
- Augmentation RAM pour cache
- CPU plus rapides pour traitement
- SSD pour logs et cache
- Réseau plus rapide

**Scalabilité horizontale :**
- Déploiement multi-instances
- Load balancing APIs
- Partitionnement zones DNS
- Distribution géographique

---

### 10 Exemples de configuration

**Configuration service :**
```ini
[phpipam]
api_url = http://phpipam.example.com/api
app_id = pphook
username = pphook_user
password = secure_password

[powerdns]
api_url = http://powerdns.example.com:8081/api/v1
api_key = your_api_key_here
server = localhost

[email]
smtp_server = smtp.example.com
smtp_port = 25
from = pphook@example.com
to = admin@example.com
use_tls = False
generic_email = admin@example.com

[validation]
hostname_pattern = ^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$
max_hostname_length = 63

[script]
check_interval = 60
last_check_file = /var/lib/pphook/last_check
```

**Variables d'environnement :**
```bash
# Base de données
DB_IP=192.168.1.100
DB_PORT=3306
PDNS_DB_USER=pdns_user
PDNS_DB_PASS=secure_password
IPAM_DB_USER=ipam_user
IPAM_DB_PASS=secure_password

# Services
PDNS_IP=192.168.1.101
PDNS_PORT=8081
IPAM_IP=192.168.1.102
SMTP_SERVER=192.168.1.103
```

*Document confidentiel - Usage interne uniquement*