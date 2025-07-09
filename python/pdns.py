#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module PowerDNS API simplifié pour l'intégration phpIPAM-PowerDNS
Fonctions essentielles uniquement pour performance optimale

Auteur: Lecoq Alexis
Date: 06/05/25
Version: 2.0
"""

import requests
import logging
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time

logger = logging.getLogger("pphook")

class PowerDNSAPI:
    """Classe PowerDNS"""
    
    def __init__(self, api_url, api_key, server="localhost"):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.server = server
        self.session = self._create_session()
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        
        # Cache DNS simple
        self._zones_cache = None
        self._zones_cache_time = 0
        self._zones_cache_ttl = 3600  # 1 heure
    
    def _create_session(self):
            """Crée une session HTTP optimisée"""
            session = requests.Session()
            
            retry_strategy = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST", "PATCH"]
            )
            
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=8,
                pool_maxsize=15
            )
            
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            session.timeout = (3, 20)
            
            session.headers.update({
                'User-Agent': 'PPHOOK-PowerDNS/2.0',
                'Accept': 'application/json'
            })
            
            return session

    def get_zones(self, clean=True, use_cache=True):
        """
        Récupère la liste des zones DNS avec cache optionnel
        
        API: GET /api/v1/servers/{server}/zones
        Params: 
            clean (bool) - Si True, retourne noms sans point final
            use_cache (bool) - Si True, utilise le cache (TTL 1h)
        Returns: list[str] - Liste des noms de zones
        """
        # Vérifier le cache si demandé
        if use_cache and self._zones_cache is not None:
            cache_age = time.time() - self._zones_cache_time
            if cache_age < self._zones_cache_ttl:
                logger.debug(f"Cache DNS hit: {len(self._zones_cache)} zones (âge: {int(cache_age)}s)")
                return self._zones_cache.copy()
        
        # Cache manqué ou désactivé - appel API
        try:
            response = self.session.get(
                f"{self.api_url}/servers/{self.server}/zones",
                headers=self.headers
            )
            response.raise_for_status()
            
            zones_data = response.json()
            
            if clean:
                # Nettoyer les noms (enlever point final)
                clean_zones = []
                for zone in zones_data:
                    name = zone.get("name", "")
                    if name.endswith('.'):
                        name = name[:-1]
                    if name:
                        clean_zones.append(name.lower())
                
                result = clean_zones
            else:
                # Retourner les données brutes
                result = zones_data
            
            # Mettre à jour le cache si clean=True (seul cas où on cache)
            if use_cache and clean:
                self._zones_cache = result.copy()
                self._zones_cache_time = time.time()
                logger.debug(f"Cache DNS mis à jour: {len(result)} zones")
            
            logger.debug(f"Récupéré {len(result)} zones DNS depuis l'API")
            return result
                
        except Exception as e:
            logger.error(f"Erreur get_zones: {e}")
            
            # En cas d'erreur, retourner le cache s'il existe
            if use_cache and self._zones_cache is not None:
                logger.warning("Erreur API - utilisation du cache expiré")
                return self._zones_cache.copy()
            
            return []

    def get_record(self, zone_name, record_name, record_type):
        """
        Récupère un enregistrement DNS spécifique
        
        API: GET /api/v1/servers/{server}/zones/{zone}
        Params:
            zone_name (str) - Nom de la zone
            record_name (str) - Nom de l'enregistrement  
            record_type (str) - Type (A, PTR, etc.)
        Returns: dict|None - Enregistrement trouvé ou None
        """
        # Normaliser les noms (ajouter point final)
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
        if not record_name.endswith('.'):
            record_name = f"{record_name}."
            
        try:
            response = self.session.get(
                f"{self.api_url}/servers/{self.server}/zones/{zone_name}",
                headers=self.headers
            )
            
            if response.status_code == 404:
                logger.debug(f"Zone {zone_name} non trouvée")
                return None
            
            response.raise_for_status()
            zone_data = response.json()
            
            # Chercher l'enregistrement dans les rrsets
            for rrset in zone_data.get("rrsets", []):
                if rrset["name"] == record_name and rrset["type"] == record_type:
                    return rrset
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur get_record {record_name} ({record_type}) dans {zone_name}: {e}")
            return None

    def create_record(self, zone_name, record_name, record_type, content, ttl=3600):
        """
        Crée ou met à jour un enregistrement DNS
        
        API: PATCH /api/v1/servers/{server}/zones/{zone}
        Params:
            zone_name (str) - Nom de la zone
            record_name (str) - Nom de l'enregistrement
            record_type (str) - Type (A, PTR, etc.)
            content (str) - Contenu de l'enregistrement
            ttl (int) - TTL en secondes
        Returns: bool - True si succès
        """
        # Normaliser les noms
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
        if not record_name.endswith('.'):
            record_name = f"{record_name}."
        
        # Vérifier si l'enregistrement existe déjà avec le bon contenu
        existing = self.get_record(zone_name, record_name, record_type)
        if existing:
            for record in existing.get("records", []):
                if not record.get("disabled", False) and record.get("content") == content:
                    logger.debug(f"Enregistrement {record_name} ({record_type}) déjà correct")
                    return True
        
        data = {
            "rrsets": [{
                "name": record_name,
                "type": record_type,
                "ttl": ttl,
                "changetype": "REPLACE",
                "records": [{
                    "content": content,
                    "disabled": False
                }]
            }]
        }
        
        try:
            response = self.session.patch(
                f"{self.api_url}/servers/{self.server}/zones/{zone_name}",
                headers=self.headers,
                json=data
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Enregistrement {record_name} ({record_type}) créé/mis à jour")
                return True
            else:
                logger.error(f"Erreur création {record_name}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur create_record {record_name}: {e}")
            return False

    def delete_record(self, zone_name, record_name, record_type):
        """
        Supprime un enregistrement DNS
        
        API: PATCH /api/v1/servers/{server}/zones/{zone}
        Params:
            zone_name (str) - Nom de la zone
            record_name (str) - Nom de l'enregistrement
            record_type (str) - Type (A, PTR, etc.)
        Returns: bool - True si succès
        """
        # Normaliser les noms
        if not zone_name.endswith('.'):
            zone_name = f"{zone_name}."
        if not record_name.endswith('.'):
            record_name = f"{record_name}."
        
        data = {
            "rrsets": [{
                "name": record_name,
                "type": record_type,
                "changetype": "DELETE"
            }]
        }
        
        try:
            response = self.session.patch(
                f"{self.api_url}/servers/{self.server}/zones/{zone_name}",
                headers=self.headers,
                json=data
            )
            
            if response.status_code == 204:
                logger.info(f"Enregistrement {record_name} ({record_type}) supprimé")
                return True
            else:
                logger.error(f"Erreur suppression {record_name}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur delete_record {record_name}: {e}")
            return False

    def validate_hostname_domain(self, hostname, zones):
        """
        Valide qu'un hostname correspond à une zone existante
        
        API: Aucun (validation locale)
        Params:
            hostname (str) - Hostname à valider
            zones (list[str]) - Liste des zones existantes
        Returns: tuple (bool, str|None, str|None) - (is_valid, zone, error_message)
        """
        try:
            hostname = hostname.lower().strip()
            
            # Vérifier format de base
            if '.' not in hostname:
                return False, None, "Le hostname doit contenir au moins un domaine"
            
            parts = hostname.split('.')
            name = parts[0]
            domain = '.'.join(parts[1:])
            
            # Vérifier que le nom n'a pas de point
            if '.' in name:
                return False, None, f"Le nom '{name}' ne doit pas contenir de point"
            
            # Chercher la zone correspondante
            if domain in zones:
                return True, domain, None
            
            # Essayer des zones plus générales
            for i in range(1, len(parts)):
                potential_zone = '.'.join(parts[i:])
                if potential_zone in zones:
                    return True, potential_zone, None
            
            return False, None, f"Aucune zone trouvée pour le domaine '{domain}'"
            
        except Exception as e:
            logger.error(f"Erreur validate_hostname_domain {hostname}: {e}")
            return False, None, f"Erreur de validation: {e}"

    def get_ptr_name_from_ip(self, ip):
        """
        Génère le nom PTR à partir d'une IP
        
        API: Aucun (calcul local)
        Params: ip (str) - Adresse IP
        Returns: str|None - Nom PTR ou None si erreur
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                octets = str(ip_obj).split('.')
                return f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
            else:
                # IPv6 - logique simplifiée
                ip_exploded = ip_obj.exploded
                ip_nibbles = ''.join(ip_exploded.replace(':', ''))
                return '.'.join(reversed(ip_nibbles)) + '.ip6.arpa.'
        except ValueError:
            logger.error(f"IP invalide: {ip}")
            return None

    def get_reverse_zone_from_ip(self, ip):
        """
        Détermine la zone reverse à partir d'une IP
        
        API: Aucun (calcul local)
        Params: ip (str) - Adresse IP
        Returns: str|None - Zone reverse ou None si erreur
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                octets = str(ip_obj).split('.')
                return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
            else:
                # IPv6 - logique simplifiée pour /64
                ip_exploded = ip_obj.exploded
                ip_nibbles = ''.join(ip_exploded.replace(':', ''))
                return '.'.join(reversed(ip_nibbles[:16])) + '.ip6.arpa.'
        except ValueError:
            logger.error(f"IP invalide: {ip}")
            return None

    def close(self):
        """Ferme la session HTTP"""
        if hasattr(self, 'session'):
            self.session.close()
    
    def find_zone_for_hostname(self, hostname, zones):
        """
        Trouve la zone DNS valide pour un hostname avec logique de recherche flexible
        
        API: Aucun (traitement local)
        Params: 
            hostname (str) - Hostname à analyser
            zones (list[str]) - Liste des zones disponibles
        Returns: str|None - Zone trouvée ou None
        """
        try:
            hostname = hostname.lower().strip()
            
            # Enlever le point final si présent
            if hostname.endswith('.'):
                hostname = hostname[:-1]
            
            if '.' not in hostname:
                return None
            
            parts = hostname.split('.')
            
            # Tester différentes combinaisons de zones, de la plus spécifique à la plus générale
            for i in range(1, len(parts)):
                potential_zone = '.'.join(parts[i:])
                if potential_zone in zones:
                    logger.debug(f"Zone trouvée pour {hostname}: {potential_zone}")
                    return potential_zone
            
            logger.debug(f"Aucune zone trouvée pour {hostname}")
            return None
            
        except Exception as e:
            logger.error(f"Erreur find_zone_for_hostname {hostname}: {e}")
            return None
    
    def check_dns_status(self, hostname, ip, zones):
        """
        Vérifie l'état DNS pour un hostname/IP et retourne toutes les infos nécessaires
        
        Args:
            hostname (str): Nom d'hôte
            ip (str): Adresse IP
            zones (list[str]): Liste des zones DNS disponibles
            
        Returns:
            tuple: (status, details)
                status (str): "no_records", "a_only", "ptr_only", "both_exist"
                details (dict): {
                    'zone_found': str,
                    'reverse_zone': str,
                    'reverse_zone_exists': bool,
                    'ptr_name': str,
                    'a_content': str|None,
                    'ptr_content': str|None,
                    'a_record': dict|None,
                    'ptr_record': dict|None
                }
        """
        try:
            # Trouver la zone forward
            zone_found = self.find_zone_for_hostname(hostname, zones)
            if not zone_found:
                logger.warning(f"Aucune zone trouvée pour {hostname}")
                return "error", {"error": "No zone found"}
            
            # Calculer les infos PTR
            reverse_zone = self.get_reverse_zone_from_ip(ip)
            ptr_name = self.get_ptr_name_from_ip(ip)
            
            # Vérifier si la zone reverse existe
            reverse_zone_exists = False
            if reverse_zone:
                reverse_zone_clean = reverse_zone.rstrip('.')
                reverse_zone_exists = reverse_zone_clean in zones
            
            logger.debug(f"DNS Status Check: zone={zone_found}, reverse_zone={reverse_zone}, reverse_exists={reverse_zone_exists}")
            
            # Vérifier les enregistrements existants
            a_record = self.get_record(zone_found, hostname, "A")
            ptr_record = None
            
            if reverse_zone_exists and ptr_name:
                ptr_record = self.get_record(reverse_zone, ptr_name, "PTR")
            
            # Extraire les contenus
            a_content = None
            ptr_content = None
            
            if a_record:
                for record in a_record.get("records", []):
                    if not record.get("disabled", False):
                        a_content = record.get("content")
                        break
            
            if ptr_record:
                for record in ptr_record.get("records", []):
                    if not record.get("disabled", False):
                        ptr_content = record.get("content")
                        break
            
            # Déterminer le statut
            has_a = a_record is not None
            has_ptr = ptr_record is not None
            
            if not has_a and not has_ptr:
                status = "no_records"
            elif has_a and not has_ptr:
                status = "a_only"
            elif not has_a and has_ptr:
                status = "ptr_only"
            elif has_a and has_ptr:
                status = "both_exist"
            else:
                status = "error"
            
            # Préparer les détails
            details = {
                'zone_found': zone_found,
                'reverse_zone': reverse_zone,
                'reverse_zone_exists': reverse_zone_exists,
                'ptr_name': ptr_name,
                'a_content': a_content,
                'ptr_content': ptr_content,
                'a_record': a_record,
                'ptr_record': ptr_record
            }
            
            logger.info(f"DNS Status: {status} (A={has_a}, PTR={has_ptr})")
            
            return status, details
            
        except Exception as e:
            logger.error(f"Erreur check_dns_status pour {hostname}: {e}")
            return "error", {"error": str(e)}

    def handle_dns_case(self, case_type, hostname, ip, details, error_callback=None):
        """
        Traite un cas DNS spécifique selon la logique métier
        
        Args:
            case_type (str): "no_records", "a_only", "ptr_only", "both_exist"
            hostname (str): Nom d'hôte
            ip (str): Adresse IP
            details (dict): Détails retournés par check_dns_status()
            error_callback (callable): Fonction de callback pour les erreurs
            
        Returns:
            tuple: (success, corrected)
                success (bool): True si l'opération a réussi
                corrected (bool): True si une correction a été effectuée
        """
        try:
            logger.info(f"Traitement cas DNS: {case_type} pour {hostname} ({ip})")
            
            if case_type == "no_records":
                # CAS 1: Pas d'A ni PTR - Entrée d'inventaire - Ne rien faire
                logger.info("CAS 1: Aucun enregistrement DNS - entrée d'inventaire - rien à faire")
                return True, False
                
            elif case_type == "a_only":
                # CAS 2: A existe, pas de PTR - Vérifier cohérence A avant de créer PTR
                logger.info("CAS 2: A record existe, PTR manquant")
                
                a_content = details.get('a_content')
                zone_found = details.get('zone_found')
                reverse_zone = details.get('reverse_zone')
                reverse_zone_exists = details.get('reverse_zone_exists')
                ptr_name = details.get('ptr_name')
                
                logger.info(f"A record contenu: {a_content}, IP IPAM attendue: {ip}")
                
                if a_content == ip:
                    # A record cohérent - créer PTR si zone reverse existe
                    if reverse_zone_exists:
                        logger.info("A record cohérent - création PTR manquant")
                        hostname_with_dot = hostname if hostname.endswith('.') else f"{hostname}."
                        success = self.create_record(reverse_zone, ptr_name, "PTR", hostname_with_dot)
                        if success:
                            logger.info("PTR record créé avec succès")
                            return True, True
                        else:
                            logger.error("Échec création PTR record")
                            return False, False
                    else:
                        logger.debug("A record cohérent mais zone reverse indisponible - pas de création PTR")
                        return True, False
                else:
                    # A record incohérent - supprimer et notifier
                    logger.warning("A record incohérent détecté - suppression et notification")
                    success = self.delete_record(zone_found, hostname, "A")
                    if success:
                        logger.info("A record incohérent supprimé avec succès")
                        if error_callback:
                            error_callback(f"A record incohérent supprimé (pointait vers {a_content} au lieu de {ip})")
                        return True, True
                    else:
                        logger.error("Échec suppression A record incohérent")
                        return False, False
                        
            elif case_type == "ptr_only":
                # CAS 3: Pas d'A, PTR existe - Supprimer PTR orphelin (sans notification)
                logger.info("CAS 3: PTR orphelin détecté - suppression sans notification")
                
                reverse_zone = details.get('reverse_zone')
                reverse_zone_exists = details.get('reverse_zone_exists')
                ptr_name = details.get('ptr_name')
                
                if reverse_zone_exists:
                    success = self.delete_record(reverse_zone, ptr_name, "PTR")
                    if success:
                        logger.info("PTR orphelin supprimé avec succès")
                        return True, True
                    else:
                        logger.error("Échec suppression PTR orphelin")
                        return False, False
                else:
                    logger.debug("Zone reverse n'existe pas - impossible de supprimer PTR orphelin")
                    return True, False
                    
            elif case_type == "both_exist":
                # CAS 4: A et PTR existent - Vérifier cohérence des deux
                logger.info("CAS 4: A et PTR existent - vérification cohérence")
                
                a_content = details.get('a_content')
                ptr_content = details.get('ptr_content')
                zone_found = details.get('zone_found')
                reverse_zone = details.get('reverse_zone')
                ptr_name = details.get('ptr_name')
                
                logger.info(f"A record contenu: {a_content}, PTR record contenu: {ptr_content}")
                logger.info(f"IPAM attendu: IP={ip}, hostname={hostname}")
                
                # Vérifier cohérence complète
                hostname_with_dot = hostname if hostname.endswith('.') else f"{hostname}."
                
                a_coherent = (a_content == ip)
                ptr_coherent = (ptr_content == hostname_with_dot)
                
                logger.info(f"Cohérence: A={a_coherent}, PTR={ptr_coherent}")
                
                if a_coherent and ptr_coherent:
                    # Tout est cohérent - ne rien faire
                    logger.info("Enregistrements A/PTR parfaitement cohérents")
                    return True, False
                else:
                    # Incohérents - supprimer les deux et notifier
                    logger.warning("Incohérence A/PTR détectée - suppression des deux et notification")
                    
                    # Supprimer les deux
                    delete_a = self.delete_record(zone_found, hostname, "A")
                    delete_ptr = self.delete_record(reverse_zone, ptr_name, "PTR")
                    logger.info(f"Suppression A: {'OK' if delete_a else 'ÉCHEC'}, PTR: {'OK' if delete_ptr else 'ÉCHEC'}")
                    
                    success = delete_a and delete_ptr
                    if success:
                        logger.info("Enregistrements incohérents supprimés")
                        if error_callback:
                            error_callback(f"Enregistrements incohérents supprimés (A={a_content}, PTR={ptr_content})")
                        return True, True
                    else:
                        logger.error("Échec suppression enregistrements incohérents")
                        return False, False
            else:
                logger.error(f"Cas DNS inconnu: {case_type}")
                return False, False
                
        except Exception as e:
            logger.error(f"Erreur handle_dns_case {case_type} pour {hostname}: {e}")
            return False, False
        
    def cleanup_invalid_hostname_records(self, hostname, ip, zones):
        """
        Nettoie les enregistrements DNS pour un hostname invalide
        
        Args:
            hostname (str): Hostname invalide
            ip (str): Adresse IP associée
            zones (list[str]): Liste des zones disponibles
            
        Returns:
            bool: True si nettoyage réussi ou pas d'enregistrements trouvés
        """
        try:
            logger.info(f"Nettoyage enregistrements DNS pour hostname invalide: {hostname}")
            cleanup_success = True
            
            # === NETTOYAGE A RECORD ===
            found_zone = self.find_zone_for_hostname(hostname, zones)
            if found_zone:
                logger.debug(f"Suppression A record: {hostname} dans zone {found_zone}")
                success_a = self.delete_record(found_zone, hostname, "A")
                if success_a:
                    logger.info("A record supprimé avec succès")
                else:
                    logger.warning("Échec suppression A record")
                    cleanup_success = False
            else:
                logger.debug("Aucune zone trouvée pour suppression A record")
            
            # === NETTOYAGE PTR RECORD ===
            reverse_zone = self.get_reverse_zone_from_ip(ip)
            ptr_name = self.get_ptr_name_from_ip(ip)
            
            if reverse_zone and ptr_name:
                reverse_zone_clean = reverse_zone.rstrip('.')
                # ✅ VÉRIFICATION EXISTENCE ZONE REVERSE (comme dans handle_dns_case)
                if reverse_zone_clean in zones:
                    logger.debug(f"Suppression PTR record: {ptr_name} dans zone {reverse_zone}")
                    success_ptr = self.delete_record(reverse_zone, ptr_name, "PTR")
                    if success_ptr:
                        logger.info("PTR record supprimé avec succès")
                    else:
                        logger.warning("Échec suppression PTR record")
                        cleanup_success = False
                else:
                    logger.debug("Zone reverse n'existe pas - skip suppression PTR")
            else:
                logger.debug("Impossible de calculer PTR - skip suppression")
            
            if cleanup_success:
                logger.info(f"Nettoyage terminé avec succès pour {hostname}")
            else:
                logger.warning(f"Nettoyage partiellement échoué pour {hostname}")
            
            return cleanup_success
            
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage pour {hostname}: {e}")
            return False

    def __del__(self):
        """Destructeur"""
        self.close()