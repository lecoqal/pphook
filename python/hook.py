#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 ___  ___  ________  ________  ___  __        ________  ___    ___
|\  \|\  \|\   __  \|\   __  \|\  \|\  \     |\   __  \|\  \  /  /|
\ \  \\\  \ \  \|\  \ \  \|\  \ \  \/  /|_   \ \  \|\  \ \  \/  / /
 \ \   __  \ \  \\\  \ \  \\\  \ \   ___  \   \ \   ____\ \    / /
  \ \  \ \  \ \  \\\  \ \  \\\  \ \  \\ \  \ __\ \  \___|\/  /  /
   \ \__\ \__\ \_______\ \_______\ \__\\ \__\\__\ \__\ __/  / /
    \|__|\|__|\|_______|\|_______|\|__| \|__\|__|\|__||\___/ /
                                                      \|___|/


Script hook pour l'intégration entre phpIPAM et PowerDNS
Ce script:
1. Récupère les nouvelles entrées depuis l'API phpIPAM
2. Utilise l'API PowerDNS pour vérifier et gérer les enregistrements DNS
3. Assure la cohérence entre les enregistrements A et PTR
4. Envoie des alertes par e-mail en cas d'erreur
5. S'exécute périodiquement pour synchroniser les deux systèmes

Auteur: Lecoq Alexis
Date: 06/05/25
Version: 2.0
"""

# =================================================
#  +-----------------------------------------+
#  |                 IMPORTS                 |
#  +-----------------------------------------+
# =================================================

import requests
import json
import re
import time
import logging
import smtplib
import os
import subprocess
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ipaddress
import configparser
import base64
import importlib

# Import explicite du module datetime standard
std_datetime = importlib.import_module('datetime')
datetime = std_datetime.datetime
timedelta = std_datetime.timedelta

# Import des modules personnalisés
from pdns import PowerDNSAPI as pdns
from phpipam import PhpIPAMAPI as ipam

# =================================================
#  +-----------------------------------------+
#  |           CONFIGURATION LOG             |
#  +-----------------------------------------+
# =================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/pphook.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("pphook")

# =================================================
#  +-----------------------------------------+
#  |       CHARGEMENT CONFIGURATION          |
#  +-----------------------------------------+
# =================================================

def load_config(config_file="/opt/pphook/config.ini"):
    config = configparser.ConfigParser()

    if not os.path.exists(config_file):
        logger.error(f"Fichier de configuration {config_file} non trouvé")
        sys.exit(1)

    config.read(config_file)
    return config

CONFIG = load_config()

# =================================================
#  +-----------------------------------------+
#  |       VARIABLES GLOBALES / CONFIG       |
#  +-----------------------------------------+
# =================================================

# Configuration phpIPAM
PHPIPAM_URL = CONFIG.get('phpipam', 'api_url')
PHPIPAM_APP_ID = CONFIG.get('phpipam', 'app_id')
PHPIPAM_USERNAME = CONFIG.get('phpipam', 'username')
PHPIPAM_PASSWORD = CONFIG.get('phpipam', 'password')

# Configuration PowerDNS
POWERDNS_URL = CONFIG.get('powerdns', 'api_url')
POWERDNS_API_KEY = CONFIG.get('powerdns', 'api_key')
POWERDNS_SERVER = CONFIG.get('powerdns', 'server', fallback='localhost')

# Configuration e-mail
SMTP_SERVER = CONFIG.get('email', 'smtp_server')
SMTP_PORT = CONFIG.getint('email', 'smtp_port', fallback=25)
SMTP_USERNAME = CONFIG.get('email', 'username', fallback=None)
SMTP_PASSWORD = CONFIG.get('email', 'password', fallback=None)
SMTP_USE_TLS = CONFIG.getboolean('email', 'use_tls', fallback=False)
EMAIL_FROM = CONFIG.get('email', 'from')
EMAIL_TO = CONFIG.get('email', 'to')

# Configuration des vérifications
HOSTNAME_PATTERN = re.compile(CONFIG.get('validation', 'hostname_pattern'))
MAX_HOSTNAME_LENGTH = CONFIG.getint('validation', 'max_hostname_length', fallback=63)

# Configuration du script
CHECK_INTERVAL = CONFIG.getint('script', 'check_interval', fallback=60)  # 1 minute par défaut
LAST_CHECK_FILE = CONFIG.get('script', 'last_check_file', fallback='/var/lib/pphook/last_check')

# =================================================
#  +-----------------------------------------+
#  |           FONCTIONS VALIDATION          |
#  +-----------------------------------------+
# =================================================

def validate_hostname(hostname):
    """Valide le format d'un nom d'hôte"""
    try:
        # Vérifier la longueur
        if len(hostname) > MAX_HOSTNAME_LENGTH:
            return False, f"Le nom d'hôte est trop long (max {MAX_HOSTNAME_LENGTH} caractères)"

        # Vérifier le format avec une expression régulière
        if not HOSTNAME_PATTERN.match(hostname):
            return False, f"Le nom d'hôte ne respecte pas le format requis (doit se terminer par .kreizenn.bzh)"

        return True, "Nom d'hôte valide"
    except Exception as e:
        logger.error(f"Erreur lors de la validation du hostname {hostname}: {str(e)}")
        return False, f"Erreur de validation: {str(e)}"

def validate_ip_address(ip):
    """Valide une adresse IP"""
    try:
        ipaddress.ip_address(ip)
        return True, "Adresse IP valide"
    except ValueError:
        return False, "Adresse IP invalide"

def validate_subnet_ip(ip, subnet):
    """Vérifie si l'IP appartient au sous-réseau"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        subnet_obj = ipaddress.ip_network(subnet)
        if ip_obj in subnet_obj:
            return True, "L'adresse IP appartient au sous-réseau"
        else:
            return False, f"L'adresse IP n'appartient pas au sous-réseau {subnet}"
    except ValueError as e:
        return False, str(e)

# =================================================
#  +-----------------------------------------+
#  |           FONCTIONS EMAIL               |
#  +-----------------------------------------+
# =================================================

def send_email(subject, body, recipient=None):
    """Envoie un email de notification"""
    if recipient is None:
        recipient = EMAIL_TO

    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        if SMTP_USE_TLS:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)

        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)

        server.send_message(msg)
        server.quit()

        logger.info(f"Email envoyé à {recipient}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'email: {str(e)}")
        return False

def notify_mac_duplicate(duplicate_info):
    """
    Envoie une notification pour un doublon MAC détecté et corrigé
    VERSION CORRIGÉE : Avec le bon format de liens phpIPAM
    
    Args:
        duplicate_info (dict): Informations sur le doublon détecté
    """
    mac = duplicate_info['mac']
    addresses = duplicate_info['addresses']
    removed_from = duplicate_info['removed_from']
    
    subject = f"[ALERTE MAC CORRIGÉE] Doublon d'adresse MAC automatiquement résolu: {mac}"
    
    # Extraire l'IP de base de PHPIPAM_URL
    phpipam_base = PHPIPAM_URL.replace('/api', '').replace('http://', '').replace('https://', '')
    
    body = f"""Bonjour,

Un doublon d'adresse MAC a été détecté et automatiquement corrigé dans l'infrastructure :

Adresse MAC en doublon: {mac}

ACTION AUTOMATIQUE EFFECTUÉE:
La MAC a été supprimée de l'adresse la plus récemment modifiée :
- IP: {removed_from['ip']}
- Hostname: {removed_from['hostname'] or 'Non défini'}
- Lien phpIPAM: http://{phpipam_base}/subnets/3/{removed_from['subnetId']}/address-details/{removed_from['id']}/

Toutes les adresses concernées par ce doublon:
"""
    
    for i, addr in enumerate(addresses, 1):
        status = " [MAC SUPPRIMÉE]" if addr['id'] == removed_from['id'] else ""
        body += f"""
  {i}. IP: {addr['ip']}{status}
     Hostname: {addr['hostname'] or 'Non défini'}
     Lien phpIPAM: http://{phpipam_base}/subnets/3/{addr['subnetId']}/address-details/{addr['id']}/
     Sous-réseau: {addr['subnetId']}
     Dernière modification: {addr['editDate']}
"""
    
    body += f"""
Le conflit a été résolu automatiquement. Veuillez vérifier la configuration réseau si nécessaire.

ACTIONS RECOMMANDÉES:
1. Vérifier que l'équipement concerné fonctionne correctement
2. Corriger la MAC si elle était incorrecte dans phpIPAM
3. S'assurer qu'aucun équipement physique n'utilise la même MAC

Ce message est généré automatiquement par le système de validation PPHOOK.
Veuillez ne pas répondre à ce message.
"""
    
    # Envoyer la notification
    success = send_email(subject, body)
    if success:
        logger.info(f"Notification de doublon MAC corrigé envoyée pour {mac}")
    else:
        logger.error(f"Échec d'envoi de notification pour le doublon MAC {mac}")

def notify_mac_duplicate_callback(duplicate_info):
    """
    Callback pour les notifications de doublons MAC
    Adapte les données pour la fonction notify_mac_duplicate existante
    
    Args:
        duplicate_info (dict): Infos du doublon avec clés:
            - mac: adresse MAC en doublon
            - addresses: liste des adresses concernées  
            - removed_from: adresse dont la MAC a été supprimée
            - api_url: URL de l'API phpIPAM
    """
    return notify_mac_duplicate(duplicate_info)

def notify_error(address, hostname, ip, error_message, username="Utilisateur inconnu", edit_date="Date inconnue", action=""):
    """
    Envoie une notification d'erreur par email
    VERSION CORRIGÉE : Avec le bon format de lien phpIPAM
    """
    subject = f"[ERREUR DNS] Problème avec l'entrée {hostname}"
    
    # Construire le lien phpIPAM avec le bon format
    phpipam_base = PHPIPAM_URL.replace('/api', '').replace('http://', '').replace('https://', '')
    phpipam_link = f"http://{phpipam_base}/subnets/3/{address.get('subnetId', 'UNKNOWN')}/address-details/{address.get('id', 'UNKNOWN')}/"
    
    body = f"""Bonjour,
    
Une erreur a été détectée lors de la création d'enregistrements DNS pour l'entrée suivante :

- Hostname: {hostname}
- Adresse IP: {ip}
- Lien phpIPAM: {phpipam_link}
- Dernière modification par: {username}
- Date de modification: {edit_date}
- Type d'action: {action}

Erreur détectée:
{error_message}

Cette entrée a été supprimée ou corrigée automatiquement.

ACTION RECOMMANDÉE:
Cliquez sur le lien phpIPAM ci-dessus pour vérifier et corriger l'entrée si nécessaire.

Ce message est généré automatiquement par le système PPHOOK.
Veuillez ne pas répondre à ce message.
"""
    return send_email(subject, body)

# =================================================
#  +-----------------------------------------+
#  |        FONCTIONS DE TRAITEMENT          |
#  +-----------------------------------------+
# =================================================

def process_address(phpipam, powerdns, address):
    """
    Fonction principale de traitement d'une adresse
    Avec validation stricte du hostname par rapport aux zones existantes

    Args:
        phpipam (PhpIPAMAPI): Instance de l'API phpIPAM
        powerdns (PowerDNSAPI): Instance de l'API PowerDNS
        address (dict): Dictionnaire contenant les informations de l'adresse

    Returns:
        bool: True si le traitement a réussi, False sinon
    """
    logger.info(f"Traitement de l'adresse IP {address.get('ip')} ({address.get('hostname')})")

    # Récupérer les informations sur l'utilisateur ayant effectué le dernier changement
    username = "Utilisateur inconnu"
    edit_date = "Date inconnue"
    action = "Action inconnue"

    if 'id' in address:
        try:
            # Récupérer l'historique de cette adresse
            changelog = phpipam.get_address_changelog(address['id'])

            if changelog and len(changelog) > 0:
                # Trouver la dernière entrée de modification
                last_change = changelog[0] # LIFO
                username = last_change.get('user', username)  #  Récupérer l'utilisateur ayant effectué la dernière modif
                edit_date = last_change.get('date', 'Date inconnue')  # Récupérer la date de modification
                action = last_change.get('action', 'Action inconnue')  # Récupérer le type d'action

        except Exception as e:
            logger.warning(f"Impossible de récupérer les informations de changelog pour l'adresse {address.get('id')}: {str(e)}")

    # Étape 1: Valider les données d'entrée
    valid, error_message = validate_address_data(address)
    if not valid:
        logger.error(f"Données invalides pour l'adresse {address.get('ip')}: {error_message}")
        notify_error(address, address.get('hostname', 'Non défini'), address.get('ip', 'Non défini'), error_message, username, edit_date, action)
        return False

    # Étape 2: Récupérer la liste des zones existantes
    existing_zones = powerdns.get_existing_zones()

    # Étape 3: Valider que le hostname correspond à une zone existante
    hostname = address.get('hostname')
    is_valid, domain, error = powerdns.validate_hostname_domain(hostname, existing_zones)

    # Si le hostname n'est pas valide, supprimer les enregistrements existants
    if not is_valid:
        logger.warning(f"Hostname invalide '{hostname}': {error}")

        # Supprimer les enregistrements existants pour cette IP
        ip = address.get('ip')

        # Vérifier si un PTR existe
        ptr_name = powerdns.get_ptr_name_from_ip(ip)
        reverse_zone = powerdns.get_reverse_zone_from_ip(ip)
        ptr_exists = powerdns.ensure_zone_exists(reverse_zone) and powerdns.get_record(reverse_zone, ptr_name, "PTR")

        # Chercher d'éventuels enregistrements A dans toutes les zones
        a_records_found = []
        for zone in existing_zones:
            zone_with_dot = f"{zone}."
            # Vérifier s'il y a un enregistrement A pour ce hostname dans cette zone
            if powerdns.ensure_zone_exists(zone_with_dot):
                a_record = powerdns.get_record(zone_with_dot, f"{hostname}.", "A")
                if a_record:
                    a_records_found.append((zone_with_dot, f"{hostname}."))

        # Supprimer les enregistrements trouvés
        cleanup_success = True

        # Supprimer le PTR si nécessaire
        if ptr_exists:
            logger.info(f"Suppression du PTR invalide pour {ip}")
            if not powerdns.delete_record(reverse_zone, ptr_name, "PTR"):
                cleanup_success = False
                logger.error(f"Échec de la suppression du PTR pour {ip}")

        # Supprimer les enregistrements A trouvés
        for zone, record_name in a_records_found:
            logger.info(f"Suppression de l'enregistrement A invalide {record_name} dans la zone {zone}")
            if not powerdns.delete_record(zone, record_name, "A"):
                cleanup_success = False
                logger.error(f"Échec de la suppression de l'enregistrement A {record_name} dans la zone {zone}")
            else:
                notify_error(address, address.get('hostname', 'Non défini'), address.get('ip', 'Non défini'), error, username, edit_date, action)

        return cleanup_success

    # Si le hostname est valide, continuer avec le traitement normal
    fqdn = hostname  # Le hostname est déjà au format FQDN

    # Étape 4: Vérifier l'état des enregistrements DNS actuels
    dns_status = powerdns.check_dns_records_status(fqdn, address.get('ip'))

    # Étape 5: Traiter selon le cas déterminé
    result = False

    # Cas 1: Ni A ni PTR - ne rien faire
    if dns_status == 'no_records':
        logger.info(f"Aucun enregistrement DNS pour {fqdn} ({address.get('ip')}), aucune action nécessaire")
        result = True

    # Cas 2: PTR sans A - supprimer le PTR
    elif dns_status == 'ptr_only':
        result = powerdns.handle_orphaned_ptr(fqdn, address.get('ip'))

    # Cas 3: A sans PTR - créer le PTR
    elif dns_status == 'a_only':
        result = powerdns.create_missing_ptr(fqdn, address.get('ip'))

    # Cas 4: A et PTR existent - vérifier la cohérence
    elif dns_status == 'both_exist':
        success, corrected, error_msg = powerdns.verify_record_consistency(
            fqdn, 
            address.get('ip'), 
            error_callback=lambda msg: notify_error(address, hostname, address.get('ip'), msg, username, edit_date, action)
        )
        
        if not success:
            # L'erreur a déjà été notifiée via le callback dans verify_record_consistency
            result = False
        else:
            if corrected:
                # Notifier de la correction effectuée
                notify_error(address, hostname, address.get('ip'), "Enregistrements DNS incohérents corrigés automatiquement", username, edit_date, action)
            result = True

    else:
        logger.error(f"État DNS inconnu: {dns_status}")
        result = False

    return result

def validate_address_data(address):
    """
    Valide les données d'une adresse

    Args:
        address (dict): Dictionnaire contenant les informations de l'adresse

    Returns:
        tuple: (valid, error_message)
    """
    # Vérifier la présence des champs obligatoires
    if not address.get('ip'):
        return False, "Adresse IP manquante"

    if not address.get('hostname'):
        return False, "Hostname manquant"

    if not address.get('subnetId'):
        return False, "ID de sous-réseau manquant"

    # Valider l'adresse IP
    ip_valid, ip_message = validate_ip_address(address.get('ip'))
    if not ip_valid:
        return False, ip_message

    # Valider le hostname
    hostname_valid, hostname_message = validate_hostname(address.get('hostname'))
    if not hostname_valid:
        return False, hostname_message

    return True, "Données valides"

# =================================================
#  +-----------------------------------------+
#  |      FONCTIONS DE SYNCHRONISATION       |
#  +-----------------------------------------+
# =================================================

def get_last_check_time():
    """
    Récupère la date de la dernière vérification
    Version améliorée avec meilleure gestion des formats et fallback
    """
    default_time = datetime.now() - timedelta(days=1)  # Par défaut, on vérifie les dernières 24 heures

    if os.path.exists(LAST_CHECK_FILE):
        try:
            with open(LAST_CHECK_FILE, 'r') as f:
                content = f.read().strip()

                # Essayer d'interpréter comme timestamp (format float)
                try:
                    timestamp = float(content)
                    last_check = datetime.fromtimestamp(timestamp)
                    logger.info(f"Dernière vérification lue (timestamp): {last_check}")

                    # Vérifier si la date est dans le futur (erreur)
                    if last_check > datetime.now():
                        logger.warning(f"Dernière vérification dans le futur ({last_check}), utilisation de la valeur par défaut")
                        return default_time

                    # Vérifier si la date est trop ancienne (> 7 jours)
                    if datetime.now() - last_check > timedelta(days=7):
                        logger.warning(f"Dernière vérification trop ancienne ({last_check}), limitation à 24h")
                        return default_time

                    return last_check
                except ValueError:
                    # Si ce n'est pas un timestamp, essayer comme chaîne de date
                    date_formats = [
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d"
                    ]

                    for fmt in date_formats:
                        try:
                            last_check = datetime.strptime(content, fmt)
                            logger.info(f"Dernière vérification lue (format {fmt}): {last_check}")
                            return last_check
                        except ValueError:
                            continue

                    # Si aucun format ne correspond
                    logger.error(f"Format de date non reconnu dans le fichier last_check: {content}")
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier de dernière vérification: {str(e)}")

    logger.warning(f"Utilisation de la date par défaut: {default_time}")
    return default_time

def save_last_check_time(check_time):
    """
    Enregistre la date de la dernière vérification
    Format amélioré et plus robuste
    """
    try:
        os.makedirs(os.path.dirname(LAST_CHECK_FILE), exist_ok=True)

        # Enregistrer au format timestamp (le plus fiable pour les comparaisons)
        with open(LAST_CHECK_FILE, 'w') as f:
            timestamp = check_time.timestamp()
            f.write(str(timestamp))

        # Créer un fichier compagnon avec la date en format lisible (pour débogage)
        debug_file = f"{LAST_CHECK_FILE}.txt"
        with open(debug_file, 'w') as f:
            f.write(check_time.strftime("%Y-%m-%d %H:%M:%S"))

        logger.info(f"Dernière vérification enregistrée: {check_time} (timestamp: {timestamp})")
    except OSError as e:
        logger.error(f"Erreur lors de l'enregistrement de la dernière vérification: {str(e)}")

def ensure_timestamp_format():
    """
    S'assure que le fichier last_check utilise le format timestamp
    """
    if not os.path.exists(LAST_CHECK_FILE):
        return

    try:
        with open(LAST_CHECK_FILE, 'r') as f:
            content = f.read().strip()

        # Vérifier si c'est déjà un timestamp
        try:
            float(content)
            return  # C'est déjà un timestamp, rien à faire
        except ValueError:
            # Essayer de convertir en timestamp
            date_formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"
            ]

            for fmt in date_formats:
                try:
                    dt = datetime.strptime(content, fmt)
                    # Convertir en timestamp et enregistrer
                    with open(LAST_CHECK_FILE, 'w') as f:
                        f.write(str(dt.timestamp()))
                    return
                except ValueError:
                    continue

            logger.warning(f"Impossible de convertir le contenu de last_check: {content}. Fichier réinitialisé.")
            # Supprimer le fichier s'il n'est pas convertible
            os.remove(LAST_CHECK_FILE)
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du format timestamp: {str(e)}")


# =================================================
#  +-----------------------------------------+
#  |           FONCTIONS PRINCIPALES         |
#  +-----------------------------------------+
# =================================================

def main():
    """Fonction principale"""
    logger.info("Démarrage du script d'intégration phpIPAM-PowerDNS")

    # Assurer le format timestamp pour last_check
    ensure_timestamp_format()

    # Initialiser les clients API
    phpipam = ipam(PHPIPAM_URL, PHPIPAM_APP_ID, PHPIPAM_USERNAME, PHPIPAM_PASSWORD, config=CONFIG)
    powerdns = pdns(POWERDNS_URL, POWERDNS_API_KEY, POWERDNS_SERVER, config=CONFIG)

    # Authentification à phpIPAM
    if not phpipam.authenticate():
        logger.error("Échec d'authentification à phpIPAM, arrêt du script")
        return 1

    # Récupérer la date de la dernière vérification
    last_check = get_last_check_time()

    # Récupérer les nouvelles adresses depuis la dernière vérification
    addresses = phpipam.get_addresses(since=last_check)

    if not addresses:
        logger.info("Aucune nouvelle adresse trouvée")
        save_last_check_time(datetime.now())
        return 0

    logger.info(f"Traitement de {len(addresses)} nouvelles adresses")

    # Traiter chaque nouvelle adresse
    success_count = 0
    error_count = 0

    for address in addresses:
        success = process_address(phpipam, powerdns, address)
        if success:
            success_count += 1
        else:
            error_count += 1

    # Enregistrer la date actuelle comme dernière vérification
    save_last_check_time(datetime.now())

    # Validation des doublons MAC
    logger.info("=== Validation des doublons MAC ===")
    try:
        mac_success = phpipam.validate_mac_duplicates(notification_callback=notify_mac_duplicate_callback)
        if mac_success:
            logger.info("Validation MAC terminée avec succès")
        else:
            logger.error("Erreurs lors de la validation MAC")
    except Exception as e:
        logger.error(f"Exception lors de la validation MAC: {str(e)}")

    logger.info(f"Traitement terminé: {success_count} réussites, {error_count} erreurs")

    return 0 if error_count == 0 else 1

def run_script():
    """Exécute le script en continu avec les intervalles spécifiés"""
    logger.info(f"Démarrage du service de synchronisation phpIPAM-PowerDNS")
    logger.info(f"  - Intervalle: {CHECK_INTERVAL}s (DNS + MAC)")

    last_dns_check = datetime.now()

    while True:
        try:
            current_time = datetime.now()

            # Vérification DNS
            if (current_time - last_dns_check).total_seconds() >= CHECK_INTERVAL:
                logger.info("=== Début vérification DNS ===")
                main()
                last_dns_check = current_time

            # Attendre 30 secondes
            time.sleep(30)

        except Exception as e:
            logger.error(f"Erreur inattendue: {str(e)}")
            time.sleep(60)

# =================================================
#  +-----------------------------------------+
#  |            POINT D'ENTRÉE              |
#  +-----------------------------------------+
# =================================================

if __name__ == "__main__":
    # Vérifier les arguments pour permettre un mode daemon ou une exécution unique
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_script()
    else:
        sys.exit(main())

