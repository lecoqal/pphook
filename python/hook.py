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
from jinja2 import Environment, FileSystemLoader

# Configuration Jinja2
env = Environment(loader=FileSystemLoader("/opt/pphook/templates/"))

# Import explicite du module datetime standard
std_datetime = importlib.import_module('datetime')
datetime = std_datetime.datetime
timedelta = std_datetime.timedelta

# Import des modules personnalisés
from pdns import PowerDNSAPI
from phpipam import PhpIPAMAPI

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
GENERIC_EMAIL = CONFIG.get('email', 'generic_email')

# Configuration des vérifications
HOSTNAME_PATTERN = re.compile(CONFIG.get('validation', 'hostname_pattern'))
MAX_HOSTNAME_LENGTH = CONFIG.getint('validation', 'max_hostname_length', fallback=63)

# Configuration du script
CHECK_INTERVAL = CONFIG.getint('script', 'check_interval', fallback=60)  # 1 minute par défaut
LAST_CHECK_FILE = CONFIG.get('script', 'last_check_file', fallback='/var/lib/pphook/last_check')
EMAIL_TEMPLATE_MAC_DUPLICATE = "email_mac_duplicate.j2"
EMAIL_TEMPLATE_HOSTNAME_DUPLICATE = "email_hostname_duplicate.j2"
EMAIL_TEMPLATE_DNS_ERROR = "email_dns_error.j2"
BYPASS_FILE = "/var/lib/pphook/bypass_protection"

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
            return False, f"Le nom d'hôte ne respecte pas le format requis"

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

def send_email(subject, body_content, recipient):
    """Envoie un email simple - recipient obligatoire"""
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body_content, 'plain', 'utf-8'))

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
        logger.error(f"Erreur envoi email: {str(e)}")
        return False

def notify_error(address, hostname, ip, error_message, username="Utilisateur inconnu", 
                edit_date="Date inconnue", action="", duplicate_address=None, duplicate_mac=None, user_email=None, use_generic_email=False):
    """Notification d'erreur universelle - user_email obligatoire"""
    try:
        if not user_email:
            logger.error(f"Pas d'email utilisateur pour notifier l'erreur: {error_message}")
            return False
            
        # Déterminer template et sujet
        if duplicate_address:
            template_name = EMAIL_TEMPLATE_HOSTNAME_DUPLICATE
            subject = f"[DOUBLON HOSTNAME] {hostname}"
        elif duplicate_mac:
            template_name = EMAIL_TEMPLATE_MAC_DUPLICATE
            subject = f"[DOUBLON MAC] {duplicate_mac}"
        else:
            template_name = EMAIL_TEMPLATE_DNS_ERROR
            subject = f"[ERREUR DNS] {hostname}"
        
        # Variables communes
        template_vars = {
            'address': address,
            'hostname': hostname,
            'ip': ip,
            'error_message': error_message,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip_ipam': PHPIPAM_URL.replace('/api', '').replace('http://', '').replace('https://', ''),
            'subnet_id': address.get('subnetId', 'Inconnu'),
            'address_id': address.get('id', 'Inconnu'),
            'duplicate_mac': duplicate_mac
        }
        
        # Ajouter les infos changelog SEULEMENT si on n'utilise pas l'email générique
        if not use_generic_email:
            template_vars.update({
                'username': username,
                'edit_date': edit_date,
                'action': action
            })
        else:
            # Pour l'email générique, on met des valeurs par défaut
            template_vars.update({
                'username': "Email générique (pas de changelog)",
                'edit_date': "Non disponible",
                'action': "Non disponible"
            })
        
        # Variables spécifiques aux doublons hostname
        if duplicate_address:
            template_vars.update({
                'duplicate_address_ip': duplicate_address.get('ip'),
                'duplicate_subnet_id': duplicate_address.get('subnetId'),
                'duplicate_address_id': duplicate_address.get('id')
            })
        
        # Rendu du template
        template = env.get_template(template_name)
        content = template.render(**template_vars)
        
        return send_email(subject, content, user_email)
        
    except Exception as e:
        logger.error(f"Erreur notification: {str(e)}")
        return False

def notify_mac_duplicate_callback(duplicate_info):
    """Callback pour doublons MAC avec email de l'utilisateur responsable"""
    try:
        removed_from = duplicate_info['removed_from']
        addresses = duplicate_info['addresses']
        
        # Récupérer l'email de l'utilisateur responsable de l'adresse supprimée
        phpipam = PhpIPAMAPI(PHPIPAM_URL, PHPIPAM_APP_ID, PHPIPAM_USERNAME, PHPIPAM_PASSWORD, config=CONFIG)
        phpipam.authenticate()
        
        user_email, username = phpipam.get_user_email_from_changelog(removed_from['id'])
        
        if not user_email:
            logger.error(f"Impossible de récupérer l'email pour le doublon MAC {duplicate_info['mac']}")
            return False
        
        # Trouver l'adresse gardée
        kept_address = next((addr for addr in addresses if addr['ip'] != removed_from['ip']), None)
        
        # Utiliser le template MAC
        template = env.get_template(EMAIL_TEMPLATE_MAC_DUPLICATE)
        content = template.render(
            ip=removed_from['ip'],
            hostname=removed_from.get('hostname', 'Non défini'),
            subnet_id=removed_from.get('subnetId', 'Inconnu'),
            address_id=removed_from.get('id', 'Inconnu'),
            ip_target=kept_address['ip'] if kept_address else 'Inconnu',
            hostname_target=kept_address.get('hostname', 'Non défini') if kept_address else 'Inconnu',
            subnet_id_target=kept_address.get('subnetId', 'Inconnu') if kept_address else 'Inconnu',
            address_id_target=kept_address.get('id', 'Inconnu') if kept_address else 'Inconnu',
            duplicate_mac=duplicate_info['mac'],
            username=username,
            edit_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        subject = f"[DOUBLON MAC CORRIGÉ] {duplicate_info['mac']}"
        return send_email(subject, content, user_email)
        
    except Exception as e:
        logger.error(f"Erreur callback MAC: {str(e)}")
        return False

# =================================================
#  +-----------------------------------------+
#  |        FONCTIONS DE TRAITEMENT          |
#  +-----------------------------------------+
# =================================================

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def process_address(phpipam, powerdns, address, users, zones):
    """Fonction principale de traitement d'une adresse individuelle"""
    ip = address.get('ip')
    hostname = address.get('hostname')
    address_id = address.get('id')
    
    logger.info(f"=== DÉBUT TRAITEMENT: {ip} ({hostname or 'Sans hostname'}) ===")
    
    # === RÉCUPÉRATION INFOS UTILISATEUR ===
    changelog = None
    try:
        changelog = phpipam.get_address_changelog(address_id)
        user_email, username, use_generic_email = get_user_info_from_changelog(changelog, users)
        if not user_email:
            logger.error(f"Email non disponible pour {address_id}")
            return False
        
        edit_date, action = get_changelog_details(changelog, use_generic_email)
        logger.info(f"Utilisateur: {username}, Email: {user_email}")
    except Exception as e:
        logger.info(f"Impossible de récupérer changelog pour {address_id}: {e}")
    
    # === VÉRIFIER SI EDITDATE MANQUANTE ===
    needs_editdate_update = False
    original_editdate = address.get('editDate')
    if not original_editdate or str(original_editdate).strip() == "":
        needs_editdate_update = True
        logger.info(f"Adresse {ip} sans editDate - mise à jour programmée")
    
    # === FONCTION POUR FORCER EDITDATE ===
    def force_editdate_if_needed(reason=""):
        if needs_editdate_update:
            logger.info(f"Mise à jour editDate pour {ip} ({reason})")
            if phpipam.force_editdate_update(address_id):
                logger.info(f"EditDate mise à jour pour {ip}")
                return True
            else:
                logger.warning(f"Échec mise à jour editDate pour {ip}, peut-être entrée en read-only.")
                return False
        return True
    
    # === VALIDATION DONNÉES ===
    valid, error_message = validate_address_data(address)
    if not valid:
        logger.error(f"Données invalides pour {ip}: {error_message}")
        notify_error(address, hostname, ip, error_message, username, edit_date, action, 
                    user_email=user_email, use_generic_email=use_generic_email)
        
        # === FORCER EDITDATE MÊME EN CAS D'ÉCHEC VALIDATION ===
        force_editdate_if_needed("données invalides")
        return False
    
    # === VALIDATION HOSTNAME/ZONES ===  
    is_valid, zone, error = powerdns.validate_hostname_domain(hostname, zones)
    if not is_valid:
        logger.warning(f"Hostname invalide: {hostname} - {error}")
        
        cleanup_success = powerdns.cleanup_invalid_hostname_records(hostname, ip, zones)
        
        notify_error(address, hostname, ip, f"Hostname invalide: {error}", 
                    username, edit_date, action, user_email=user_email, use_generic_email=use_generic_email)
        
        logger.info(f"Hostname invalide nettoyé: {hostname}")
        
        # === FORCER EDITDATE MÊME POUR HOSTNAME INVALIDE ===
        force_editdate_if_needed("hostname invalide")
        return cleanup_success
    
    # === TRAITEMENT DNS ===
    def dns_error_callback(msg):
        notify_error(address, hostname, ip, msg, username, edit_date, action,
                    user_email=user_email, use_generic_email=use_generic_email)
    
    try:
        # Vérifier l'état DNS
        status, details = powerdns.check_dns_status(hostname, ip, zones)
        
        if status == "error":
            logger.error(f"Erreur vérification DNS pour {hostname}")
            # === FORCER EDITDATE MÊME EN CAS D'ERREUR DNS ===
            force_editdate_if_needed("erreur DNS")
            return False
        
        # Traiter selon le cas
        success, corrected = powerdns.handle_dns_case(status, hostname, ip, details, dns_error_callback)
        
        if corrected:
            logger.info("Action DNS effectuée avec succès")
        
        # === MISE À JOUR EDITDATE ===
        force_editdate_if_needed("traitement terminé")
        
        return success
        
    except Exception as e:
        logger.error(f"Erreur traitement DNS pour {hostname}: {e}")
        # === FORCER EDITDATE MÊME EN CAS D'EXCEPTION ===
        force_editdate_if_needed("exception traitement")
        return False
    
    finally:
        logger.info(f"=== FIN TRAITEMENT: {ip} ===")

def get_user_info_from_changelog(changelog, users):
    """Récupère les infos utilisateur depuis un changelog déjà récupéré"""
    
    # Essayer d'abord de récupérer l'email utilisateur depuis le changelog
    if changelog and len(changelog) > 0:
        try:
            real_name = changelog[-1]["user"]
            # Trouver l'email dans la liste des users
            for user in users:
                if user["real_name"] == real_name:
                    return user["email"], real_name, False
            
            # User trouvé dans changelog mais pas dans la liste des users
            logger.info(f"Utilisateur '{real_name}' trouvé dans changelog mais pas dans la liste des users")
            
        except Exception as e:
            logger.info(f"Erreur extraction utilisateur depuis changelog: {e}")
    
    # Fallback sur email générique si :
    # - Pas de changelog
    # - Erreur dans le changelog  
    # - Utilisateur pas trouvé dans la liste
    if GENERIC_EMAIL and GENERIC_EMAIL.strip():
        username = changelog[-1]["user"] if changelog and len(changelog) > 0 else "Utilisateur inconnu"
        logger.info(f"Utilisation email générique pour utilisateur: {username}")
        return GENERIC_EMAIL, username, True
    
    # Aucune solution trouvée
    logger.warning("Aucun email disponible (ni utilisateur ni générique)")
    return None, None, False

def get_changelog_details(changelog, use_generic_email):
    """Récupère les détails depuis un changelog déjà récupéré"""
    if use_generic_email or not changelog or len(changelog) == 0:
        return "Date inconnue", "Action inconnue"
    
    try:
        last_change = changelog[-1]
        return last_change.get('date', 'Date inconnue'), last_change.get('action', 'Action inconnue')
    except Exception:
        return "Date inconnue", "Action inconnue"

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
    """Récupère la date de la dernière vérification"""
    default_time = datetime.now() - timedelta(days=1)
    
    # Si pas de fichier, utiliser défaut
    if not os.path.exists(LAST_CHECK_FILE):
        return default_time
    
    try:
        # Lire le timestamp
        with open(LAST_CHECK_FILE, 'r') as f:
            timestamp = float(f.read().strip())
        
        last_check = datetime.fromtimestamp(timestamp)
        logger.info(f"Dernière vérification: {last_check}")
        
        # Bypass si fichier existe
        if os.path.exists(BYPASS_FILE):
            logger.info("Bypass activé - ignore protection")
            os.remove(BYPASS_FILE)  # Supprimer après usage
            return last_check
        
        # Protection normale (> 7 jours)
        if datetime.now() - last_check > timedelta(days=7):
            logger.warning(f"Trop ancien ({last_check}), limitation à 24h")
            return default_time
            
        return last_check
        
    except Exception as e:
        logger.error(f"Erreur lecture timestamp: {e}")
        return default_time

def save_last_check_time(check_time):
    """
    Enregistre la date de la dernière vérification
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

def reset_last_check():
    """Reset timestamp avec bypass"""
    try:
        # Créer fichier bypass
        os.makedirs(os.path.dirname(BYPASS_FILE), exist_ok=True)
        with open(BYPASS_FILE, 'w') as f:
            f.write("bypass")
        
        # Reset timestamp à -20 ans
        new_time = datetime.now() - timedelta(days=365 * 20)
        with open(LAST_CHECK_FILE, 'w') as f:
            f.write(str(new_time.timestamp()))
        
        logger.info("Timestamp reset avec bypass")
        return True
    except Exception as e:
        logger.error(f"Erreur reset: {e}")
        return False

# =================================================
#  +-----------------------------------------+
#  |           FONCTIONS PRINCIPALES         |
#  +-----------------------------------------+
# =================================================

def main():
    """Fonction principale"""
    logger.info("Démarrage du script d'intégration phpIPAM-PowerDNS")
    
    success_count = 0
    error_count = 0
    
    # Initialisation des APIs
    phpipam = PhpIPAMAPI(PHPIPAM_URL, PHPIPAM_APP_ID, PHPIPAM_USERNAME, PHPIPAM_PASSWORD)
    powerdns = PowerDNSAPI(POWERDNS_URL, POWERDNS_API_KEY, POWERDNS_SERVER)
    
    if not phpipam.authenticate():
        logger.error("Échec d'authentification à phpIPAM, arrêt du script")
        return 1
    
    last_check = get_last_check_time()
    
    # =========================================================================
    # PHASE 1: RÉCUPÉRATION DES DONNÉES
    # =========================================================================
    logger.info("Récupération des données...")
    addresses = phpipam.get_addresses(since=last_check)
    users = phpipam.get_all_users()
    zones = powerdns.get_zones(clean=True, use_cache=True)
    
    logger.info(f"Données récupérées: {len(addresses)} adresses, {len(users)} utilisateurs, {len(zones)} zones DNS")
    
    if not addresses:
        logger.info("Aucune adresse à traiter")
        save_last_check_time(datetime.now())
        return 0
    
    # =========================================================================
    # PHASE 2: NETTOYAGE GLOBAL - DOUBLONS MAC
    # =========================================================================
    logger.info("=== Phase 2: Résolution doublons MAC ===")
    
    mac_duplicates = phpipam.find_mac_duplicates(addresses)
    mac_cleaned = 0
    
    for addr1, addr2 in mac_duplicates:
        try:
            # Déterminer laquelle supprimer (la plus récente)
            most_recent = phpipam.determine_most_recent(addr1, addr2)
            
            logger.info(f"Suppression MAC pour doublon: {most_recent.get('ip')} ({most_recent.get('hostname')})")
            
            if phpipam.remove_mac_from_address(most_recent.get('id')):
                mac_cleaned += 1
                # TODO: Notification email si nécessaire
            else:
                logger.error(f"Échec suppression MAC pour {most_recent.get('ip')}")
                
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage MAC: {e}")
    
    logger.info(f"Doublons MAC nettoyés: {mac_cleaned}")
    
    # =========================================================================
    # PHASE 3: NETTOYAGE GLOBAL - DOUBLONS HOSTNAME  
    # =========================================================================
    logger.info("=== Phase 3: Résolution doublons hostname ===")
    
    hostname_duplicates = phpipam.find_hostname_duplicates(addresses)
    hostname_cleaned = 0
    
    for addr1, addr2 in hostname_duplicates:
        try:
            # Déterminer laquelle supprimer (la plus récente)
            most_recent = phpipam.determine_most_recent(addr1, addr2)
            
            hostname = most_recent.get('hostname')
            ip = most_recent.get('ip')
            
            logger.info(f"Suppression doublon hostname: {hostname} ({ip})")
            
            # Supprimer les enregistrements DNS associés
            zone = powerdns.find_zone_for_hostname(hostname, zones)
            if zone:
                powerdns.delete_record(zone, hostname, "A")
            
            reverse_zone = powerdns.get_reverse_zone_from_ip(ip)
            ptr_name = powerdns.get_ptr_name_from_ip(ip)
            if reverse_zone and ptr_name:
                reverse_zone_clean = reverse_zone.rstrip('.')
                if reverse_zone_clean in zones:
                    powerdns.delete_record(reverse_zone, ptr_name, "PTR")
                else:
                    logger.info(f"Zone reverse {reverse_zone} n'existe pas - skip suppression PTR")
            
            # FIXE: Supprimer l'adresse avec la liste existante (évite appel API)
            if phpipam.delete_address(ip, addresses):
                hostname_cleaned += 1
                # Retirer l'adresse de la liste pour éviter de la traiter plus tard
                addresses = [addr for addr in addresses if addr.get('ip') != ip]
                # TODO: Notification email si nécessaire
            else:
                logger.warning(f"Échec suppression adresse {ip} (peut-être normal)")
                
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage hostname: {e}")
    
    logger.info(f"Doublons hostname nettoyés: {hostname_cleaned}")
    
    # =========================================================================
    # PHASE 4: TRAITEMENT INDIVIDUEL
    # =========================================================================
    logger.info("=== Phase 4: Traitement individuel ===")
    
    for address in addresses:
        try: 
            success = process_address(phpipam, powerdns, address, users, zones)
            
            if success:
                success_count += 1
            else:
                error_count += 1
                
        except Exception as e:
            logger.error(f"Erreur traitement pour {address.get('ip')}: {e}")
            error_count += 1
    
    # =========================================================================
    # FINALISATION
    # =========================================================================
    save_last_check_time(datetime.now())
    
    logger.info("=== RÉSUMÉ ===")
    logger.info(f"Doublons MAC nettoyés: {mac_cleaned}")
    logger.info(f"Doublons hostname nettoyés: {hostname_cleaned}")
    logger.info(f"Traitement individuel: {success_count} réussites, {error_count} erreurs")
    logger.info(f"Traitement terminé")
    
    return 0 if error_count == 0 else 1

def run_script():
    """Exécute le script en continu avec les intervalles spécifiés"""
    logger.info(f"Démarrage du service de synchronisation phpIPAM-PowerDNS")
    logger.info(f"  - Intervalle: {CHECK_INTERVAL}s (DNS + MAC)")

    last_dns_check = datetime.now() - timedelta(seconds=CHECK_INTERVAL)

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

