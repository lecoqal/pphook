#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

$$$$$$$\                                              $$$$$$$\  $$\   $$\  $$$$$$\  
$$  __$$\                                             $$  __$$\ $$$\  $$ |$$  __$$\ 
$$ |  $$ | $$$$$$\  $$\  $$\  $$\  $$$$$$\   $$$$$$\  $$ |  $$ |$$$$\ $$ |$$ /  \__|
$$$$$$$  |$$  __$$\ $$ | $$ | $$ |$$  __$$\ $$  __$$\ $$ |  $$ |$$ $$\$$ |\$$$$$$\  
$$  ____/ $$ /  $$ |$$ | $$ | $$ |$$$$$$$$ |$$ |  \__|$$ |  $$ |$$ \$$$$ | \____$$\ 
$$ |      $$ |  $$ |$$ | $$ | $$ |$$   ____|$$ |      $$ |  $$ |$$ |\$$$ |$$\   $$ |
$$ |      \$$$$$$  |\$$$$$\$$$$  |\$$$$$$$\ $$ |      $$$$$$$  |$$ | \$$ |\$$$$$$  |
\__|       \______/  \_____\____/  \_______|\__|      \_______/ \__|  \__| \______/ 
                                                                                    
                                                                                   
Module PowerDNS API pour l'intégration phpIPAM-PowerDNS
Fonctions:
- Vérification et création de zones DNS
- Création d'enregistrements A et PTR
- Suppression d'enregistrements

Auteur: Lecoq Alexis
Date: 06/05/25
Version: 1.2
"""

import requests
import logging
import ipaddress
import json
logger = logging.getLogger("pphook")

class PowerDNSAPI:
    """Classe pour interagir avec l'API PowerDNS - Version étendue"""
    
    def __init__(self, api_url, api_key, server, config=None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.server = server
        self.config = config
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
    
    def get_zones(self):
        """
        Récupère la liste de toutes les zones configurées dans PowerDNS
        avec une gestion robuste des erreurs
        
        Returns:
            list: Liste des zones configurées ou liste vide en cas d'erreur
        """
        zones_url = f"{self.api_url}/servers/{self.server}/zones"
        
        try:
            response = requests.get(zones_url, headers=self.headers)
            
            if response.status_code == 200:
                zones = response.json()
                logger.debug(f"Récupération de {len(zones)} zones")
                return zones
            else:
                logger.error(f"Erreur lors de la récupération des zones: {response.status_code}")
                if response.text:
                    logger.error(f"Détails: {response.text}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Exception lors de la récupération des zones: {str(e)}")
            return []
        except ValueError as e:
            logger.error(f"Erreur lors du parsing JSON: {str(e)}")
            return []
    
    def get_zone(self, zone_name):
        """
        Récupère une zone spécifique par son nom
        
        Args:
            zone_name (str): Nom de la zone à récupérer
            
        Returns:
            dict: Données de la zone ou None si non trouvée
        """
        # S'assurer que zone_name se termine par un point
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
            
        zone_url = f"{self.api_url}/servers/{self.server}/zones/{zone_name}"
        
        try:
            response = requests.get(zone_url, headers=self.headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.warning(f"Zone {zone_name} non trouvée")
                return None
            else:
                logger.error(f"Erreur lors de la récupération de la zone {zone_name}: {response.status_code}")
                if response.text:
                    logger.error(f"Détails: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Exception lors de la récupération de la zone {zone_name}: {str(e)}")
            return None
        except ValueError as e:
            logger.error(f"Erreur lors du parsing JSON: {str(e)}")
            return None
    
    def get_record(self, zone_name, record_name, record_type):
        """Récupère un enregistrement DNS spécifique"""
        zone = self.get_zone(zone_name)
        if not zone:
            return None
            
        # S'assurer que record_name se termine par un point
        if not record_name.endswith('.'):
            record_name = f"{record_name}."
            
        # Chercher l'enregistrement dans les rrsets de la zone
        for rrset in zone.get("rrsets", []):
            if rrset["name"] == record_name and rrset["type"] == record_type:
                return rrset
                
        return None
            
    def ensure_zone_exists(self, zone_name):
        """
        Vérifie si une zone existe en utilisant l'API PowerDNS.
        Implémentation robuste qui gère les erreurs spécifiquement.
        
        Args:
            zone_name (str): Nom de la zone à vérifier
            
        Returns:
            bool: True si la zone existe, False sinon
        """
        # S'assurer que zone_name se termine par un point
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
            
        zone_url = f"{self.api_url}/servers/{self.server}/zones/{zone_name}"
        
        try:
            response = requests.get(zone_url, headers=self.headers)
            
            # 200 OK = zone existe
            if response.status_code == 200:
                return True
                
            # 404 NOT FOUND = zone n'existe pas
            elif response.status_code == 404:
                logger.debug(f"Zone {zone_name} non trouvée")
                return False
                
            # 422 UNPROCESSABLE ENTITY = généralement un problème de format
            # PowerDNS peut renvoyer 422 si le format de la zone est incorrect
            elif response.status_code == 422:
                logger.debug(f"Format de zone incorrect pour {zone_name}")
                return False
                
            # Autre cas d'erreur
            else:
                logger.error(f"Erreur lors de la récupération de la zone {zone_name}: {response.status_code}")
                if response.text:
                    logger.error(f"Détails: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Exception lors de la récupération de la zone {zone_name}: {str(e)}")
            return False

    def create_record(self, zone_name, record_name, record_type, content, ttl=3600):
        """
        Crée ou met à jour un enregistrement DNS
        Version corrigée pour gérer le bug "Changetype not understood"
        """
        # Vérifier que la zone existe
        if not self.ensure_zone_exists(zone_name):
            logger.error(f"La zone {zone_name} n'existe pas, impossible de créer l'enregistrement")
            return False
            
        # S'assurer que zone_name et record_name se terminent par un point
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
            
        if not record_name.endswith('.'):
            record_name = f"{record_name}."
            
        zone_url = f"{self.api_url}/servers/{self.server}/zones/{zone_name}"
        
        # Vérifier si l'enregistrement existe déjà
        existing_record = self.get_record(zone_name, record_name, record_type)
        
        changetype = "REPLACE"  # Utiliser REPLACE par défaut car c'est généralement plus sûr
        
        # Si l'enregistrement existe et a déjà le bon contenu, ne rien faire
        if existing_record:
            current_content = None
            for record in existing_record.get("records", []):
                if not record.get("disabled", False):
                    current_content = record.get("content")
                    break
                    
            if current_content == content:
                logger.info(f"L'enregistrement {record_name} ({record_type}) existe déjà avec le bon contenu dans la zone {zone_name}")
                return True
        
        # Préparer les données pour la requête API
        data = {
            "rrsets": [
                {
                    "name": record_name,
                    "type": record_type,
                    "ttl": ttl,
                    "changetype": changetype,
                    "records": [
                        {
                            "content": content,
                            "disabled": False
                        }
                    ]
                }
            ]
        }
        
        try:
            response = requests.patch(zone_url, headers=self.headers, json=data)
            if response.status_code in [200, 204]:
                logger.info(f"Enregistrement {record_name} ({record_type}) créé/mis à jour avec succès dans la zone {zone_name}")
                return True
            else:
                logger.error(f"Erreur lors de la création/mise à jour de l'enregistrement {record_name}: {response.status_code}, {response.text}")
                
                # Si l'erreur est "Changetype not understood", essayer sans "changetype"
                if "Changetype not understood" in response.text:
                    logger.info(f"Tentative de création sans spécifier 'changetype'")
                    # Supprimer le changetype dans la requête
                    data["rrsets"][0].pop("changetype", None)
                    
                    try:
                        response = requests.patch(zone_url, headers=self.headers, json=data)
                        if response.status_code in [200, 204]:
                            logger.info(f"Enregistrement {record_name} ({record_type}) créé/mis à jour avec succès dans la zone {zone_name}")
                            return True
                        else:
                            logger.error(f"Nouvelle tentative échouée: {response.status_code}, {response.text}")
                    except Exception as e:
                        logger.error(f"Exception lors de la nouvelle tentative: {str(e)}")
                
                return False
        except Exception as e:
            logger.error(f"Erreur lors de la création/mise à jour de l'enregistrement {record_name}: {str(e)}")
            return False
                       
    def delete_record(self, zone_name, record_name, record_type):
        """Supprime un enregistrement DNS"""
        # Vérifier que la zone existe
        if not self.ensure_zone_exists(zone_name):
            logger.error(f"La zone {zone_name} n'existe pas, impossible de supprimer l'enregistrement")
            return False
            
        # S'assurer que zone_name et record_name se terminent par un point
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
            
        if not record_name.endswith('.'):
            record_name = f"{record_name}."
            
        zone_url = f"{self.api_url}/servers/{self.server}/zones/{zone_name}"
        
        data = {
            "rrsets": [
                {
                    "name": record_name,
                    "type": record_type,
                    "changetype": "DELETE"
                }
            ]
        }
        
        try:
            response = requests.patch(zone_url, headers=self.headers, json=data)
            if response.status_code == 204:
                logger.info(f"Enregistrement {record_name} ({record_type}) supprimé avec succès de la zone {zone_name}")
                return True
            else:
                logger.error(f"Erreur lors de la suppression de l'enregistrement {record_name}: {response.status_code}, {response.text}")
                return False
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de l'enregistrement {record_name}: {str(e)}")
            return False
            
    def get_ptr_name_from_ip(self, ip):
        """
        Génère le nom PTR à partir d'une adresse IP
        Exemple: 192.168.1.10 -> 10.1.168.192.in-addr.arpa.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # Pour IPv4, inversion des octets
                octets = str(ip_obj).split('.')
                return f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
            else:
                # Pour IPv6, inversion des nibbles
                ip_exploded = ip_obj.exploded
                ip_nibbles = ''.join(ip_exploded.replace(':', ''))
                reverse = '.'.join(reversed(ip_nibbles)) + '.ip6.arpa.'
                return reverse
        except ValueError:
            logger.error(f"Adresse IP invalide: {ip}")
            return None
            
    def get_reverse_zone_from_ip(self, ip):
        """
        Détermine la zone de reverse DNS à partir d'une adresse IP
        Exemple: 192.168.1.10 -> 1.168.192.in-addr.arpa.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # Pour IPv4, on utilise généralement les 3 premiers octets inversés
                octets = str(ip_obj).split('.')
                return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
            else:
                # Pour IPv6, logique simplifiée (peut nécessiter ajustement selon votre découpage de zones)
                ip_exploded = ip_obj.exploded
                ip_nibbles = ''.join(ip_exploded.replace(':', ''))
                # Utilise typiquement un /64 pour IPv6
                reverse = '.'.join(reversed(ip_nibbles[:16])) + '.ip6.arpa.'
                return reverse
        except ValueError:
            logger.error(f"Adresse IP invalide: {ip}")
            return None
        
    def create_a_ptr_records(self, hostname, ip, ttl=3600):
        """
        Crée ou met à jour les enregistrements A et PTR pour un hostname et une IP
        Retourne (success, error_message)
        """
        # S'assurer que hostname se termine par un point
        if not hostname.endswith('.'):
            hostname = f"{hostname}."
            
        # Obtenir la zone forward
        parts = hostname.split('.')
        if len(parts) < 3:
            return False, f"Format FQDN invalide: {hostname}"
            
        forward_zone = '.'.join(parts[-3:-1]) + '.'
        
        # Vérifier l'existence de la zone forward
        if not self.ensure_zone_exists(forward_zone):
            return False, f"La zone forward {forward_zone} n'existe pas"
            
        # Récupérer le nom PTR et la zone reverse
        ptr_name = self.get_ptr_name_from_ip(ip)
        reverse_zone = self.get_reverse_zone_from_ip(ip)
        
        # Vérifier l'existence de la zone reverse
        if not self.ensure_zone_exists(reverse_zone):
            return False, f"La zone reverse {reverse_zone} n'existe pas"
            
        # Créer/mettre à jour l'enregistrement A
        a_success = self.create_record(forward_zone, hostname, "A", ip, ttl)
        if not a_success:
            return False, f"Échec de création/mise à jour de l'enregistrement A pour {hostname}"
            
        # Créer/mettre à jour l'enregistrement PTR
        ptr_success = self.create_record(reverse_zone, ptr_name, "PTR", hostname, ttl)
        if not ptr_success:
            # Si l'A a réussi mais pas le PTR, on pourrait envisager de supprimer l'A
            # pour maintenir la cohérence, mais on laisse cette décision au code appelant
            return False, f"Échec de création/mise à jour de l'enregistrement PTR pour {ip}"
            
        return True, None
        
    def delete_a_ptr_records(self, hostname, ip):
        """
        Supprime les enregistrements A et PTR associés
        Retourne (success, error_message)
        """
        # S'assurer que hostname se termine par un point
        if not hostname.endswith('.'):
            hostname = f"{hostname}."
            
        # Obtenir la zone forward
        parts = hostname.split('.')
        if len(parts) < 3:
            return False, f"Format FQDN invalide: {hostname}"
            
        forward_zone = '.'.join(parts[-3:-1]) + '.'
        
        # Récupérer le nom PTR et la zone reverse
        ptr_name = self.get_ptr_name_from_ip(ip)
        reverse_zone = self.get_reverse_zone_from_ip(ip)
        
        # Vérifier l'existence des zones
        forward_exists = self.ensure_zone_exists(forward_zone)
        reverse_exists = self.ensure_zone_exists(reverse_zone)
        
        success = True
        errors = []
        
        # Supprimer l'enregistrement A s'il existe
        if forward_exists:
            a_success = self.delete_record(forward_zone, hostname, "A")
            if not a_success:
                success = False
                errors.append(f"Échec de suppression de l'enregistrement A pour {hostname}")
        
        # Supprimer l'enregistrement PTR s'il existe
        if reverse_exists:
            ptr_success = self.delete_record(reverse_zone, ptr_name, "PTR")
            if not ptr_success:
                success = False
                errors.append(f"Échec de suppression de l'enregistrement PTR pour {ip}")
        
        if not success:
            return False, "; ".join(errors)
            
        return True, None

    def get_existing_zones(self):
        """
        Récupère la liste des zones DNS existantes dans PowerDNS

        Args:
            powerdns (PowerDNSAPI): Instance de l'API PowerDNS

        Returns:
            list: Liste des noms de zones sans le point final
        """
        zones = self.get_zones()
        # Nettoyer les noms de zones (enlever le point final)
        clean_zones = []
        for zone in zones:
            name = zone.get("name", "")
            if name.endswith('.'):
                name = name[:-1]
            if name:
                clean_zones.append(name.lower())

        logger.debug(f"Zones existantes: {clean_zones}")
        return clean_zones

    def validate_hostname_domain(self, hostname, existing_zones=None):
        """
        Valide qu'un hostname correspond à une zone existante
        En suivant la règle: hostname = nom.domaine où nom n'a pas de point
        et domaine doit correspondre à une zone existante

        Args:
            hostname (str): Le hostname à valider
            existing_zones (list): Liste des zones existantes

        Returns:
            tuple: (is_valid, domain, error_message)
        """
        # S'assurer que le hostname est en minuscules
        hostname = hostname.lower()

        # Vérifier s'il y a au moins un point dans le hostname
        if '.' not in hostname:
            return False, None, "Le hostname doit contenir au moins un domaine (format: nom.domaine)"

        # Diviser en nom et domaine
        parts = hostname.split('.')
        name = parts[0]
        domain = '.'.join(parts[1:])

        # Vérifier que le nom ne contient pas de point
        if '.' in name:
            return False, None, f"Le nom '{name}' ne doit pas contenir de point"

        # Vérifier que le domaine correspond à une zone existante
        if domain not in existing_zones:
            return False, None, f"Le domaine '{domain}' ne correspond à aucune zone DNS existante"

        return True, domain, None

    def check_dns_records_status(self, fqdn, ip):
        """
        Détermine l'état actuel des enregistrements DNS pour une paire hostname/IP
        avec stratégie de détection de zone améliorée pour une meilleure compatibilité

        Args:
            powerdns (PowerDNSAPI): Instance de l'API PowerDNS
            fqdn (str): Nom d'hôte complet
            ip (str): Adresse IP

        Returns:
            str: État des enregistrements ('no_records', 'a_only', 'ptr_only', 'both_exist')
        """
        # S'assurer que fqdn se termine par un point pour la comparaison DNS
        if not fqdn.endswith('.'):
            fqdn_with_dot = f"{fqdn}."
        else:
            fqdn_with_dot = fqdn

        # Stratégie flexible pour trouver la zone correcte
        domain_parts = fqdn_with_dot.split('.')

        # Tester différentes combinaisons de zones possibles, de la plus spécifique à la plus générale
        possible_zones = []

        # Générer des zones candidates à partir du FQDN
        for i in range(1, len(domain_parts)):
            zone_candidate = '.'.join(domain_parts[i:])
            if zone_candidate:  # Éviter les chaînes vides
                possible_zones.append(zone_candidate)

        logger.debug(f"Zones possibles pour {fqdn_with_dot}: {possible_zones}")

        # Chercher la première zone qui existe
        forward_zone = None
        for zone in possible_zones:
            if self.ensure_zone_exists(zone):
                forward_zone = zone
                logger.debug(f"Zone trouvée: {forward_zone}")
                break

        if not forward_zone:
            logger.warning(f"Aucune zone valide trouvée pour {fqdn}. Zones testées: {possible_zones}")
            return 'no_records'

        # Vérifier l'existence de l'enregistrement A
        a_record = self.get_record(forward_zone, fqdn_with_dot, "A")

        # Récupérer le nom et la zone PTR
        ptr_name = self.get_ptr_name_from_ip(ip)
        reverse_zone = self.get_reverse_zone_from_ip(ip)

        # Vérifier si la zone reverse existe
        reverse_zone_exists = self.ensure_zone_exists(reverse_zone)

        # Vérifier l'existence de l'enregistrement PTR si la zone existe
        ptr_record = None
        if reverse_zone_exists:
            ptr_record = self.get_record(reverse_zone, ptr_name, "PTR")

        # Déterminer l'état
        if not a_record and (not reverse_zone_exists or not ptr_record):
            return 'no_records'
        elif a_record and (not reverse_zone_exists or not ptr_record):
            return 'a_only'
        elif not a_record and reverse_zone_exists and ptr_record:
            return 'ptr_only'
        elif a_record and reverse_zone_exists and ptr_record:
            return 'both_exist'

        # Ce cas ne devrait pas arriver
        logger.error(f"État indéterminé pour {fqdn} ({ip})")
        return 'error'
    
    def handle_orphaned_ptr(self, fqdn, ip):
        """
        Gère le cas d'un enregistrement PTR sans enregistrement A associé
        Dans ce cas, on supprime le PTR orphelin

        Args:
            powerdns (PowerDNSAPI): Instance de l'API PowerDNS
            fqdn (str): Nom d'hôte complet
            ip (str): Adresse IP

        Returns:
            bool: True si l'opération a réussi, False sinon
        """
        logger.info(f"Suppression du PTR orphelin pour {ip} (pointant vers {fqdn})")

        # Récupérer le nom et la zone PTR
        ptr_name = self.get_ptr_name_from_ip(ip)
        reverse_zone = self.get_reverse_zone_from_ip(ip)

        # Supprimer l'enregistrement PTR
        success = self.delete_record(reverse_zone, ptr_name, "PTR")

        if success:
            logger.info(f"PTR orphelin supprimé avec succès pour {ip}")
        else:
            logger.error(f"Échec de la suppression du PTR orphelin pour {ip}")

        return success

    def create_missing_ptr(self, fqdn, ip):
        """
        Crée un enregistrement PTR manquant pour un enregistrement A existant

        Args:
            powerdns (PowerDNSAPI): Instance de l'API PowerDNS
            fqdn (str): Nom d'hôte complet
            ip (str): Adresse IP

        Returns:
            bool: True si l'opération a réussi, False sinon
        """
        logger.info(f"Création du PTR manquant pour {ip} (pointant vers {fqdn})")

        # S'assurer que fqdn se termine par un point
        if not fqdn.endswith('.'):
            fqdn = f"{fqdn}."

        # Récupérer le nom et la zone PTR
        ptr_name = self.get_ptr_name_from_ip(ip)
        reverse_zone = self.get_reverse_zone_from_ip(ip)

        # Vérifier l'existence de la zone reverse
        if not self.ensure_zone_exists(reverse_zone):
            logger.error(f"La zone reverse {reverse_zone} n'existe pas, impossible de créer le PTR")
            return False

        # Créer l'enregistrement PTR
        success = self.create_record(reverse_zone, ptr_name, "PTR", fqdn)

        if success:
            logger.info(f"PTR créé avec succès pour {ip} -> {fqdn}")
        else:
            logger.error(f"Échec de la création du PTR pour {ip} -> {fqdn}")

        return success

    def verify_record_consistency(self, fqdn, ip, error_callback=None):
        """
        Vérifie la cohérence entre les enregistrements A et PTR existants
        
        Args:
            fqdn (str): Nom d'hôte complet
            ip (str): Adresse IP
            error_callback (callable): Fonction de callback pour les erreurs (optionnel)
        
        Returns:
            tuple: (success, corrected, error_message)
        """
        logger.info(f"Vérification de la cohérence des enregistrements DNS pour {fqdn} ({ip})")

        # S'assurer que fqdn se termine par un point
        if not fqdn.endswith('.'):
            fqdn_with_dot = f"{fqdn}."
        else:
            fqdn_with_dot = fqdn

        # Stratégie flexible pour trouver la zone correcte
        domain_parts = fqdn_with_dot.split('.')

        # Tester différentes combinaisons de zones possibles
        possible_zones = []
        for i in range(1, len(domain_parts)):
            zone_candidate = '.'.join(domain_parts[i:])
            if zone_candidate:  # Éviter les chaînes vides
                possible_zones.append(zone_candidate)

        # Chercher la première zone qui existe
        forward_zone = None
        for zone in possible_zones:
            if self.ensure_zone_exists(zone):
                forward_zone = zone
                break

        if not forward_zone:
            error_msg = f"Aucune zone valide trouvée pour {fqdn_with_dot}"
            logger.warning(error_msg)
            return False, False, error_msg

        # Récupérer l'enregistrement A
        a_record = self.get_record(forward_zone, fqdn_with_dot, "A")
        if not a_record:
            error_msg = f"Enregistrement A non trouvé pour {fqdn_with_dot}"
            logger.warning(error_msg)
            return False, False, error_msg

        # Récupérer le nom et la zone PTR
        ptr_name = self.get_ptr_name_from_ip(ip)
        reverse_zone = self.get_reverse_zone_from_ip(ip)

        # Vérifier l'existence de la zone reverse
        if not self.ensure_zone_exists(reverse_zone):
            error_msg = f"Zone reverse {reverse_zone} non trouvée"
            logger.warning(error_msg)
            return False, False, error_msg

        # Récupérer l'enregistrement PTR
        ptr_record = self.get_record(reverse_zone, ptr_name, "PTR")
        if not ptr_record:
            error_msg = f"Enregistrement PTR non trouvé pour {ip}"
            logger.warning(error_msg)
            return False, False, error_msg

        # Vérifier que les enregistrements A et PTR se correspondent
        a_content = None
        ptr_content = None

        # Extraire le contenu de l'enregistrement A
        for record in a_record.get("records", []):
            if not record.get("disabled", False):
                a_content = record.get("content")
                break

        # Extraire le contenu de l'enregistrement PTR
        for record in ptr_record.get("records", []):
            if not record.get("disabled", False):
                ptr_content = record.get("content")
                break

        # Vérifier la cohérence
        if not a_content or not ptr_content:
            error_msg = f"Contenu des enregistrements non trouvé pour {fqdn_with_dot} / {ip}"
            logger.warning(error_msg)
            return False, False, error_msg

        if a_content != ip:
            error_msg = f"L'enregistrement A pointe vers {a_content} mais l'IP attendue est {ip}"
            logger.warning(error_msg)
            inconsistent = True
        elif ptr_content != fqdn_with_dot:
            error_msg = f"L'enregistrement PTR pointe vers {ptr_content} mais le hostname attendu est {fqdn_with_dot}"
            logger.warning(error_msg)
            inconsistent = True
        else:
            logger.info(f"Les enregistrements A et PTR sont cohérents pour {fqdn_with_dot} ({ip})")
            return True, False, None

        # Corriger l'incohérence en recréant les deux enregistrements
        logger.info(f"Tentative de correction de l'incohérence pour {fqdn_with_dot} ({ip})")

        # Supprimer les enregistrements existants
        success, delete_error = self.delete_a_ptr_records(fqdn_with_dot, ip)
        if not success:
            error_msg = f"Échec de la suppression des enregistrements incohérents: {delete_error}"
            logger.error(error_msg)
            return False, False, error_msg
        else:
            # Notifier la suppression via callback si fourni
            if error_callback:
                error_callback(f"Suppression des enregistrements A et PTR incohérents pour {fqdn_with_dot}")

        # Recréer les enregistrements
        success, create_error = self.create_a_ptr_records(fqdn_with_dot, ip)
        if not success:
            error_msg = f"Échec de la recréation des enregistrements: {create_error}"
            logger.error(error_msg)
            return False, False, error_msg

        logger.info(f"Correction réussie des enregistrements DNS pour {fqdn_with_dot} ({ip})")
        return True, True, None
