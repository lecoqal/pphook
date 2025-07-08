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

def process_address(phpipam, powerdns, address, users, zones):
    """Fonction principale de traitement d'une adresse individuelle"""
    ip = address.get('ip')
    hostname = address.get('hostname')
    
    logger.info(f"=== DÉBUT TRAITEMENT: {ip} ({hostname}) ===")
    
    # === RÉCUPÉRATION CHANGELOG ===
    logger.debug("Étape 1: Récupération changelog")
    changelog = None
    try:
        changelog = phpipam.get_address_changelog(address.get('id'))
        if changelog:
            logger.debug(f"Changelog récupéré: {len(changelog)} entrées")
        else:
            logger.debug("Aucun changelog trouvé")
    except Exception as e:
        logger.debug(f"Impossible de récupérer changelog pour {address.get('id')}: {e}")
    
    # === INFOS UTILISATEUR DEPUIS CHANGELOG ===
    logger.debug("Étape 2: Récupération infos utilisateur")
    user_email, username, use_generic_email = get_user_info_from_changelog(changelog, users)
    if not user_email:
        logger.error(f"Email non disponible pour notifier l'erreur pour {address.get('id')}")
        return False
    
    logger.debug(f"Email utilisateur: {user_email} (générique: {use_generic_email})")
    edit_date, action = get_changelog_details(changelog, use_generic_email)
    logger.debug(f"Changelog détails: {username}, {edit_date}, {action}")
    
    # === MAINTENANCE DONNÉES (AVANT TRAITEMENT) ===
    maintenance_editdate = not address.get('editDate') or str(address.get('editDate')).strip() == ""
    maintenance_changelog = not changelog or len(changelog) == 0
    logger.debug(f"Maintenance requise - editDate: {maintenance_editdate}, changelog: {maintenance_changelog}")
    
    # === ÉTAPE 1: VALIDATION DONNÉES ===
    logger.info("Étape 3: Validation des données")
    valid, error_message = validate_address_data(address)
    if not valid:
        logger.error(f"Données invalides pour {ip}: {error_message}")
        notify_error(address, hostname, ip, error_message, username, edit_date, action, 
                    user_email=user_email, use_generic_email=use_generic_email)
        return False
    logger.info("Validation des données: OK")
    
    # === ÉTAPE 2: VALIDATION HOSTNAME/ZONES ===
    logger.info("Étape 4: Validation hostname/zones DNS")
    
    # Valider le hostname contre les zones DNS
    is_valid, zone, error = powerdns.validate_hostname_domain(hostname, zones)
    logger.info(f"Validation hostname: valid={is_valid}, zone={zone}, error={error}")
    
    if not is_valid:
        logger.warning(f"Hostname invalide détecté: {hostname} ({ip}) - {error}")
        
        # Supprimer les enregistrements DNS existants
        logger.info("Nettoyage des enregistrements DNS pour hostname invalide")
        found_zone = powerdns.find_zone_for_hostname(hostname, zones)
        logger.debug(f"Zone trouvée pour nettoyage A: {found_zone}")
        
        if found_zone:
            success_a = powerdns.delete_record(found_zone, hostname, "A")
            logger.info(f"Suppression A record: {'OK' if success_a else 'ÉCHEC'}")
        else:
            logger.debug("Pas de zone trouvée pour suppression A record")
        
        reverse_zone = powerdns.get_reverse_zone_from_ip(ip)
        ptr_name = powerdns.get_ptr_name_from_ip(ip)
        logger.debug(f"Zone reverse calculée: {reverse_zone}, PTR name: {ptr_name}")
        
        if reverse_zone and ptr_name:
            reverse_zone_clean = reverse_zone.rstrip('.')
            if reverse_zone_clean in zones:
                success_ptr = powerdns.delete_record(reverse_zone, ptr_name, "PTR")
                logger.info(f"Suppression PTR record: {'OK' if success_ptr else 'ÉCHEC'}")
            else:
                logger.debug("Zone reverse n'existe pas - skip suppression PTR")
        else:
            logger.debug("Impossible de calculer PTR pour suppression")
        
        # Notifier l'utilisateur
        notify_error(address, hostname, ip, f"Hostname invalide: {error}", 
                    username, edit_date, action, user_email=user_email, use_generic_email=use_generic_email)
        
        logger.info(f"Hostname invalide nettoyé: {hostname}")
        return True  # Considéré comme succès (nettoyage fait)
    
    logger.info("Validation hostname/zones: OK")
    
    # === ÉTAPE 3: TRAITEMENT COHÉRENCE DNS ===
    logger.info("Étape 5: Traitement cohérence DNS")
    
    def dns_error_callback(msg):
        logger.warning(f"DNS error callback: {msg}")
        notify_error(address, hostname, ip, msg, username, edit_date, action,
                    user_email=user_email, use_generic_email=use_generic_email)

    try:
        # Trouver la zone pour ce hostname
        logger.debug("Recherche zone forward pour hostname")
        zone_found = powerdns.find_zone_for_hostname(hostname, zones)
        logger.info(f"Zone forward trouvée: {zone_found}")
        
        if not zone_found:
            logger.warning(f"Aucune zone trouvée pour {hostname}")
            success = False
        else:
            # Calculer les infos PTR
            logger.debug("Calcul des informations PTR")
            reverse_zone = powerdns.get_reverse_zone_from_ip(ip)
            ptr_name = powerdns.get_ptr_name_from_ip(ip)
            
            logger.info(f"Zone reverse calculée: {reverse_zone}")
            logger.info(f"PTR name calculé: {ptr_name}")
            
            # Vérifier si la zone reverse existe dans PowerDNS
            reverse_zone_exists = False
            if reverse_zone:
                reverse_zone_clean = reverse_zone.rstrip('.')
                if reverse_zone_clean in zones:
                    reverse_zone_exists = True
                    logger.debug(f"Zone reverse {reverse_zone} confirmée dans PowerDNS")
                else:
                    logger.warning(f"Zone reverse {reverse_zone} n'existe pas dans PowerDNS")
            
            # Vérifier l'état actuel des enregistrements
            logger.debug("Vérification état des enregistrements DNS")
            logger.info(f"Recherche A record: {hostname} dans zone: {zone_found}")
            a_record = powerdns.get_record(zone_found, hostname, "A")
            
            if a_record:
                logger.info(f"A record trouvé")
            else:
                logger.info(f"A record NOT FOUND pour {hostname} dans {zone_found}")
            
            ptr_record = None
            if reverse_zone_exists and ptr_name:
                logger.info(f"Recherche PTR record: {ptr_name} dans zone: {reverse_zone}")
                ptr_record = powerdns.get_record(reverse_zone, ptr_name, "PTR")
                if ptr_record:
                    logger.info(f"PTR record trouvé")
                else:
                    logger.info(f"PTR record NOT FOUND pour {ptr_name} dans {reverse_zone}")
            else:
                logger.debug("Skip vérification PTR (zone reverse indisponible)")
            
            # Déterminer l'action selon l'état
            has_a = a_record is not None
            has_ptr = ptr_record is not None
            corrected = False
            
            logger.info(f"ÉTAT FINAL DNS: A record={has_a}, PTR record={has_ptr}")
            
            # === LOGIQUE DES 4 CAS ===
            
            if not has_a and not has_ptr:
                # CAS 1: Pas d'A ni PTR - Entrée d'inventaire - Ne rien faire
                logger.info(f"CAS 1: Aucun enregistrement DNS pour {hostname} ({ip}) - entrée d'inventaire - rien à faire")
                success = True
                
            elif has_a and not has_ptr:
                # CAS 2: A existe, pas de PTR - Vérifier cohérence A avant de créer PTR
                logger.info(f"CAS 2: A record existe, PTR manquant pour {hostname} ({ip})")
                
                # Extraire le contenu de l'A record
                a_content = None
                for record in a_record.get("records", []):
                    if not record.get("disabled", False):
                        a_content = record.get("content")
                        break
                
                logger.info(f"A record contenu: {a_content}, IP IPAM attendue: {ip}")
                
                if a_content == ip:
                    # A record cohérent - créer PTR si zone reverse existe
                    if reverse_zone_exists:
                        logger.info("A record cohérent - création PTR manquant")
                        hostname_with_dot = hostname if hostname.endswith('.') else f"{hostname}."
                        success = powerdns.create_record(reverse_zone, ptr_name, "PTR", hostname_with_dot)
                        if success:
                            logger.info("PTR record créé avec succès")
                            corrected = True
                        else:
                            logger.error("Échec création PTR record")
                    else:
                        logger.warning("A record cohérent mais zone reverse indisponible - pas de création PTR")
                        success = True  # On considère que c'est OK
                else:
                    # A record incohérent - supprimer et notifier
                    logger.warning(f"A record incohérent détecté - suppression et notification")
                    success = powerdns.delete_record(zone_found, hostname, "A")
                    if success:
                        logger.info("A record incohérent supprimé avec succès")
                        dns_error_callback(f"A record incohérent supprimé (pointait vers {a_content} au lieu de {ip})")
                        corrected = True
                    else:
                        logger.error("Échec suppression A record incohérent")
                
            elif not has_a and has_ptr:
                # CAS 3: Pas d'A, PTR existe - Supprimer PTR orphelin (sans notification)
                logger.info(f"CAS 3: PTR orphelin détecté pour {ip} - suppression sans notification")
                success = powerdns.delete_record(reverse_zone, ptr_name, "PTR")
                if success:
                    logger.info("PTR orphelin supprimé avec succès")
                    corrected = True
                else:
                    logger.error("Échec suppression PTR orphelin")
                
            elif has_a and has_ptr:
                # CAS 4: A et PTR existent - Vérifier cohérence des deux
                logger.info(f"CAS 4: A et PTR existent - vérification cohérence pour {hostname} ({ip})")
                
                # Extraire les contenus
                a_content = None
                ptr_content = None
                
                for record in a_record.get("records", []):
                    if not record.get("disabled", False):
                        a_content = record.get("content")
                        break
                
                for record in ptr_record.get("records", []):
                    if not record.get("disabled", False):
                        ptr_content = record.get("content")
                        break
                
                logger.info(f"A record contenu: {a_content}, PTR record contenu: {ptr_content}")
                logger.info(f"IPAM attendu: IP={ip}, hostname={hostname}")
                
                # Vérifier cohérence complète
                hostname_with_dot = hostname if hostname.endswith('.') else f"{hostname}."
                
                a_coherent = (a_content == ip)
                ptr_coherent = (ptr_content == hostname_with_dot)
                
                logger.info(f"Cohérence: A={a_coherent}, PTR={ptr_coherent}")
                
                if a_coherent and ptr_coherent:
                    # Tout est cohérent - ne rien faire
                    logger.info(f"Enregistrements A/PTR parfaitement cohérents pour {hostname}")
                    success = True
                else:
                    # Incohérents - supprimer les deux et notifier
                    logger.warning(f"Incohérence A/PTR détectée - suppression des deux et notification")
                    logger.info("Suppression des enregistrements incohérents")
                    
                    # Supprimer les deux
                    delete_a = powerdns.delete_record(zone_found, hostname, "A")
                    delete_ptr = powerdns.delete_record(reverse_zone, ptr_name, "PTR")
                    logger.info(f"Suppression A: {'OK' if delete_a else 'ÉCHEC'}, PTR: {'OK' if delete_ptr else 'ÉCHEC'}")
                    
                    success = delete_a and delete_ptr
                    if success:
                        logger.info(f"Enregistrements incohérents supprimés pour {hostname}")
                        dns_error_callback(f"Enregistrements incohérents supprimés (A={a_content}, PTR={ptr_content})")
                        corrected = True
                    else:
                        logger.error(f"Échec suppression enregistrements incohérents pour {hostname}")
            
            # Log final du cas traité
            if corrected:
                logger.info("Action DNS effectuée avec succès")
            else:
                logger.debug("Aucune action DNS requise")
            
    except Exception as e:
        logger.error(f"Erreur traitement DNS pour {hostname}: {e}")
        success = False
    
    # === MAINTENANCE DONNÉES (APRÈS TRAITEMENT RÉUSSI) ===
    if success:
        logger.debug("Traitement DNS réussi, vérification maintenance")
        if maintenance_editdate:
            # TODO: Implémenter avec les nouvelles classes simplifiées
            # update_success = phpipam.update_address_editdate(address.get('id'))
            # Pour l'instant, skip
            logger.debug(f"Maintenance editDate à implémenter pour {ip}")
        
        if maintenance_changelog:
            # TODO: Implémenter avec les nouvelles classes simplifiées  
            # changelog_success = phpipam.create_changelog_entry(address.get('id'))
            # Pour l'instant, skip
            logger.debug(f"Maintenance changelog à implémenter pour {ip}")
    else:
        logger.warning("Traitement DNS échoué - pas de maintenance")
    
    logger.info(f"=== FIN TRAITEMENT: {ip} - {'SUCCÈS' if success else 'ÉCHEC'} ===")
    return success

def get_user_info_from_changelog(changelog, users):
    """Récupère les infos utilisateur depuis un changelog déjà récupéré"""
    if not changelog or len(changelog) == 0:
        # Fallback sur email générique
        if GENERIC_EMAIL and GENERIC_EMAIL.strip():
            return GENERIC_EMAIL, "Utilisateur inconnu", True
        return None, None, False
    
    try:
        real_name = changelog[-1]["user"]
        # Trouver l'email dans la liste des users
        for user in users:
            if user["real_name"] == real_name:
                return user["email"], real_name, False
        
        # User trouvé dans changelog mais pas dans la liste des users
        if GENERIC_EMAIL and GENERIC_EMAIL.strip():
            return GENERIC_EMAIL, real_name, True
        
        return None, real_name, False
        
    except Exception:
        if GENERIC_EMAIL and GENERIC_EMAIL.strip():
            return GENERIC_EMAIL, "Utilisateur inconnu", True
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
    """Fonction principale simplifiée avec architecture optimisée"""
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
                powerdns.delete_record(reverse_zone, ptr_name, "PTR")
            
            # Supprimer l'adresse de phpIPAM
            if phpipam.delete_address(ip):
                hostname_cleaned += 1
                # Retirer l'adresse de la liste pour éviter de la traiter plus tard
                addresses = [addr for addr in addresses if addr.get('ip') != ip]
                # TODO: Notification email si nécessaire
            else:
                logger.error(f"Échec suppression adresse {ip}")
                
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage hostname: {e}")
    
    logger.info(f"Doublons hostname nettoyés: {hostname_cleaned}")
    
    # =========================================================================
    # PHASE 4: TRAITEMENT INDIVIDUEL
    # =========================================================================
    logger.info("=== Phase 5: Traitement individuel ===")
    
    for address in addresses:
        try: 
            # Cette fonction se concentrera uniquement sur la cohérence DNS A/PTR
            # sans validation/nettoyage (déjà fait dans les phases précédentes)
            
            success = process_address(address, powerdns, address, users, zones)
            
            if success:
                success_count += 1
            else:
                error_count += 1
                
        except Exception as e:
            logger.error(f"Erreur traitement DNS pour {address.get('ip')}: {e}")
            error_count += 1
    
    # =========================================================================
    # FINALISATION
    # =========================================================================
    save_last_check_time(datetime.now())
    
    logger.info("=== RÉSUMÉ ===")
    logger.info(f"Doublons MAC nettoyés: {mac_cleaned}")
    logger.info(f"Doublons hostname nettoyés: {hostname_cleaned}")
    logger.info(f"Traitement DNS: {success_count} réussites, {error_count} erreurs")
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

