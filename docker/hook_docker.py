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
from config_loader import load_config_from_docker_secrets

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

def load_config():
    """Charge la configuration depuis les Docker Secrets"""
    logger.info("Chargement de la configuration depuis les Docker Secrets...")
    config = load_config_from_docker_secrets()

    if config is None:
        logger.error("Impossible de charger la configuration")
        sys.exit(1)

    logger.info("Configuration chargée avec succès")
    return config

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

# =================================================
#  +-----------------------------------------+
#  |        FONCTIONS DE TRAITEMENT          |
#  +-----------------------------------------+
# =================================================

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
    except Exception as e:
        logger.debug(f"Impossible de récupérer changelog pour {address_id}: {e}")
    
    # MODIFICATION: Utilisation des nouvelles méthodes dans phpipam
    user_email, username, use_generic_email = phpipam.get_user_email_from_changelog(changelog, users, GENERIC_EMAIL)
    if not user_email:
        logger.error(f"Email non disponible pour {address_id}")
        return False
    
    edit_date, action = phpipam.get_changelog_summary(changelog, use_generic_email)
    logger.debug(f"Utilisateur: {username}, Email: {user_email}")
    
    # === VÉRIFIER SI EDITDATE MANQUANTE ===
    needs_editdate_update = False
    original_editdate = address.get('editDate')
    if not original_editdate or str(original_editdate).strip() == "":
        needs_editdate_update = True
        logger.debug(f"Adresse {ip} sans editDate - mise à jour programmée")
    
    # === FONCTION POUR FORCER EDITDATE ===
    def force_editdate_if_needed(reason=""):
        if needs_editdate_update:
            logger.info(f"Mise à jour editDate pour {ip} ({reason})")
            if phpipam.force_editdate_update(address_id):
                logger.debug(f"EditDate mise à jour pour {ip}")
                return True
            else:
                logger.warning(f"Échec mise à jour editDate pour {ip}")
                return False
        return True
    
    # === VALIDATION DONNÉES ===
    valid, error_message = validate_address_data(address)
    if not valid:
        logger.error(f"Données invalides pour {ip}: {error_message}")
        notify_error(address, hostname, ip, error_message, username, edit_date, action, 
                    user_email=user_email, use_generic_email=use_generic_email)
        
        # === FORCER EDITDATE ===
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
        if success:
            force_editdate_if_needed("traitement réussi")
        else:
            force_editdate_if_needed("traitement échoué")
        
        return success
        
    except Exception as e:
        logger.error(f"Erreur traitement DNS pour {hostname}: {e}")
        # === FORCER EDITDATE MÊME EN CAS D'EXCEPTION ===
        force_editdate_if_needed("exception traitement")
        return False
    
    finally:
        logger.info(f"=== FIN TRAITEMENT: {ip} ===")

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
    """Fonction principale avec notifications pour doublons"""
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
    # PHASE 2: NETTOYAGE GLOBAL - DOUBLONS MAC AVEC NOTIFICATIONS
    # =========================================================================
    logger.info("=== Phase 2: Résolution doublons MAC ===")
    
    mac_cleaned, mac_processed_items, addresses = clean_duplicates('mac', addresses, phpipam)
    
    # Notifications pour doublons MAC
    for item in mac_processed_items:
        address = item['address']
        duplicate_info = item['duplicate_info']
        
        try:
            # Récupération changelog et email utilisateur
            changelog = phpipam.get_address_changelog(address.get('id'))
            user_email, username, use_generic_email = phpipam.get_user_email_from_changelog(changelog, users, GENERIC_EMAIL)
            
            if user_email:
                # Utiliser notify_error avec duplicate_mac pour déclencher le bon template
                duplicate_mac = duplicate_info['mac']
                edit_date, action = phpipam.get_changelog_summary(changelog, use_generic_email)
                
                success = notify_error(
                    address=address,
                    hostname=address.get('hostname', 'Non défini'),
                    ip=address.get('ip'),
                    error_message=f"MAC dupliquée détectée et corrigée: {duplicate_mac}",
                    username=username,
                    edit_date=edit_date,
                    action=action,
                    duplicate_mac=duplicate_mac,
                    user_email=user_email,
                    use_generic_email=use_generic_email
                )
                
                if not success and GENERIC_EMAIL:
                    # Retry avec email générique si échec
                    logger.warning(f"Échec notification utilisateur pour MAC {duplicate_mac}, retry avec email générique")
                    notify_error(
                        address=address,
                        hostname=address.get('hostname', 'Non défini'),
                        ip=address.get('ip'),
                        error_message=f"MAC dupliquée détectée et corrigée: {duplicate_mac}",
                        username="Email générique (retry)",
                        edit_date="Non disponible",
                        action="Non disponible",
                        duplicate_mac=duplicate_mac,
                        user_email=GENERIC_EMAIL,
                        use_generic_email=True
                    )
                else:
                    logger.info(f"Notification MAC dupliquée envoyée à {user_email}")
            else:
                logger.warning(f"Impossible de notifier pour MAC dupliquée {duplicate_info['mac']} - pas d'email")
                
        except Exception as e:
            logger.error(f"Erreur notification MAC dupliquée: {e}")
    
    logger.info(f"Doublons MAC nettoyés: {mac_cleaned}")
    
    # =========================================================================
    # PHASE 3: NETTOYAGE GLOBAL - DOUBLONS HOSTNAME AVEC NOTIFICATIONS
    # =========================================================================
    logger.info("=== Phase 3: Résolution doublons hostname ===")
    
    hostname_cleaned, hostname_processed_items, addresses = phpipam.clean_duplicates('hostname', addresses, phpipam, powerdns, zones)
    
    # Notifications pour doublons hostname
    for item in hostname_processed_items:
        address = item['address']
        duplicate_info = item['duplicate_info']
        
        try:
            # Récupération changelog et email utilisateur
            changelog = phpipam.get_address_changelog(address.get('id'))
            user_email, username, use_generic_email = phpipam.get_user_email_from_changelog(changelog, users, GENERIC_EMAIL)
            
            if user_email:
                hostname = duplicate_info['hostname']
                kept_address = duplicate_info['kept_address']
                edit_date, action = phpipam.get_changelog_summary(changelog, use_generic_email)
                
                success = notify_error(
                    address=address,
                    hostname=hostname,
                    ip=address.get('ip'),
                    error_message=f"Hostname dupliqué détecté et supprimé. Adresse conservée: {kept_address.get('ip')}",
                    username=username,
                    edit_date=edit_date,
                    action=action,
                    duplicate_address=kept_address,
                    user_email=user_email,
                    use_generic_email=use_generic_email
                )
                
                if not success and GENERIC_EMAIL:
                    # Retry avec email générique si échec
                    logger.warning(f"Échec notification utilisateur pour hostname {hostname}, retry avec email générique")
                    notify_error(
                        address=address,
                        hostname=hostname,
                        ip=address.get('ip'),
                        error_message=f"Hostname dupliqué détecté et supprimé. Adresse conservée: {kept_address.get('ip')}",
                        username="Email générique (retry)",
                        edit_date="Non disponible",
                        action="Non disponible",
                        duplicate_address=kept_address,
                        user_email=GENERIC_EMAIL,
                        use_generic_email=True
                    )
                else:
                    logger.info(f"Notification hostname dupliqué envoyée à {user_email}")
            else:
                logger.warning(f"Impossible de notifier pour hostname dupliqué {duplicate_info['hostname']} - pas d'email")
                
        except Exception as e:
            logger.error(f"Erreur notification hostname dupliqué: {e}")
    
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

