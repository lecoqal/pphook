#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module phpIPAM API simplifié pour l'intégration phpIPAM-PowerDNS
Fonctions essentielles uniquement pour performance optimale

Auteur: Lecoq Alexis  
Date: 06/05/25
Version: 2.0
"""

import requests
import base64
import logging
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("pphook")

class PhpIPAMAPI:
    """Classe phpIPAM"""
    
    def __init__(self, api_url, app_id, username, password):
        self.api_url = api_url.rstrip('/')
        self.app_id = app_id
        self.username = username
        self.password = password
        self.token = None
        self.token_expires = datetime.now()
        self.session = self._create_session()
    
    def _create_session(self):
        """Crée une session HTTP optimisée"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST", "PATCH"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.timeout = (5, 30)
        
        session.headers.update({
            'User-Agent': 'PPHOOK/2.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        return session

    def authenticate(self):
        """
        Authentification à l'API phpIPAM
        
        API: POST /api/{app_id}/user/
        Returns: bool - True si succès
        """
        auth_url = f"{self.api_url}/{self.app_id}/user/"
        auth_header = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("utf-8")
        headers = {"Authorization": f"Basic {auth_header}"}
        
        try:
            response = self.session.post(auth_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                self.token = data["data"]["token"]
                self.token_expires = datetime.now() + timedelta(hours=1)
                logger.info("Authentification phpIPAM réussie")
                return True
            else:
                logger.error(f"Échec authentification: {data.get('message')}")
                return False
        except Exception as e:
            logger.error(f"Erreur authentification phpIPAM: {e}")
            return False
    
    def _ensure_auth(self):
        """S'assure que le token est valide"""
        if self.token is None or datetime.now() >= self.token_expires:
            return self.authenticate()
        return True
    
    def get_addresses(self, since=None):
        """
        Récupère les adresses IP depuis phpIPAM
        
        API: GET /api/{app_id}/addresses/
        Params: since (datetime) - Filtre par date de modification
        Returns: list[dict] - Liste des adresses actives
        """
        if not self._ensure_auth():
            return []

        try:
            response = self.session.get(
                f"{self.api_url}/{self.app_id}/addresses/",
                headers={"token": self.token}
            )
            response.raise_for_status()
            
            data = response.json()
            if not data["success"]:
                logger.error(f"Erreur get_addresses: {data.get('message')}")
                return []
            
            addresses = data["data"]
            filtered = []
            
            since_str = since.strftime("%Y-%m-%d %H:%M:%S") if since else None
            
            for addr in addresses:
                # Filtrer inactives
                if addr.get("state") == "0":
                    continue
                
                # Filtrer par date
                if since_str:
                    edit_date = addr.get("editDate")
                    if edit_date and edit_date <= since_str:
                        continue
                
                filtered.append(addr)
            
            logger.info(f"Récupéré {len(filtered)} adresses depuis phpIPAM")
            return filtered
            
        except Exception as e:
            logger.error(f"Erreur get_addresses: {e}")
            return []

    def get_address_changelog(self, address_id):
        """
        Récupère l'historique d'une adresse
        
        API: GET /api/{app_id}/addresses/{id}/changelog/
        Params: address_id (str) - ID de l'adresse
        Returns: list[dict] - Historique des modifications
        """
        if not self._ensure_auth():
            return []
        
        try:
            response = self.session.get(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/changelog/",
                headers={"token": self.token}
            )
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.debug(f"Pas de changelog pour adresse {address_id}")
                return []
                
        except Exception as e:
            logger.debug(f"Erreur changelog adresse {address_id}: {e}")
            return []

    def get_all_users(self):
        """
        Récupère tous les utilisateurs
        
        API: GET /api/{app_id}/user/all/
        Returns: list[dict] - Liste des utilisateurs
        """
        if not self._ensure_auth():
            return []
        
        try:
            response = self.session.get(
                f"{self.api_url}/{self.app_id}/user/all/",
                headers={"token": self.token}
            )
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.warning("Impossible de récupérer les utilisateurs")
                return []
                
        except Exception as e:
            logger.error(f"Erreur get_all_users: {e}")
            return []

    def has_mac_and_dhcp_profil(self, address):
        """
        Vérifie si une adresse a une MAC et un profil DHCP valide
        
        API: Aucun (validation locale)
        Params: address (dict) - Adresse à vérifier
        Returns: tuple (bool, str|None, str|None) - (has_valid, mac, dhcp_profil)
        """
        try:
            # Vérifier MAC
            mac_value = address.get('mac')
            if not mac_value or str(mac_value).strip() == '':
                return False, None, None
            
            # Normaliser MAC
            mac_clean = str(mac_value).lower().strip()
            
            # Vérifier profil DHCP
            dhcp_profil = address.get('custom_DHCP_Profil')
            if not dhcp_profil:
                return False, mac_clean, None
            
            dhcp_profil_clean = str(dhcp_profil).lower().strip()
            if dhcp_profil_clean not in ['infra', 'lise']:
                return False, mac_clean, dhcp_profil_clean
            
            return True, mac_clean, dhcp_profil_clean
            
        except Exception as e:
            logger.warning(f"Erreur validation MAC/DHCP pour adresse {address.get('id')}: {e}")
            return False, None, None

    def delete_address(self, ip):
        """
        Supprime une adresse par son IP
        
        API: GET /api/{app_id}/addresses/ + DELETE /api/{app_id}/addresses/{id}/
        Params: ip (str) - Adresse IP à supprimer
        Returns: bool - True si suppression réussie
        """
        if not self._ensure_auth():
            return False
        
        try:
            # Trouver l'ID de l'adresse
            all_addresses = self.get_addresses()  # Utilise le cache si possible
            address_id = None
            
            for addr in all_addresses:
                if addr.get('ip') == ip:
                    address_id = addr.get('id')
                    break
            
            if not address_id:
                logger.warning(f"Adresse {ip} non trouvée pour suppression")
                return False
            
            # Supprimer l'adresse
            response = self.session.delete(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success", False):
                    logger.info(f"Adresse {ip} supprimée avec succès")
                    return True
            
            logger.error(f"Échec suppression adresse {ip}: {response.status_code}")
            return False
            
        except Exception as e:
            logger.error(f"Erreur delete_address {ip}: {e}")
            return False

    def create_address(self, ip, hostname, subnet_id, **kwargs):
        """
        Crée ou met à jour une adresse
        
        API: POST /api/{app_id}/addresses/
        Params: 
            ip (str) - Adresse IP
            hostname (str) - Nom d'hôte
            subnet_id (str) - ID du sous-réseau
            **kwargs - Champs additionnels (mac, description, etc.)
        Returns: bool - True si création réussie
        """
        if not self._ensure_auth():
            return False
        
        try:
            payload = {
                "ip": ip,
                "hostname": hostname,
                "subnetId": subnet_id,
                "state": "2",  # Active par défaut
                **kwargs
            }
            
            response = self.session.post(
                f"{self.api_url}/{self.app_id}/addresses/",
                headers={"token": self.token},
                json=payload
            )
            
            if response.status_code in [200, 201]:
                # Gestion des réponses vides de phpIPAM
                if response.text.strip():
                    result = response.json()
                    if result.get("success", True):
                        logger.info(f"Adresse {ip} créée avec succès")
                        return True
                else:
                    logger.info(f"Adresse {ip} créée avec succès (réponse vide)")
                    return True
            
            logger.error(f"Échec création adresse {ip}: {response.status_code}")
            return False
            
        except Exception as e:
            logger.error(f"Erreur create_address {ip}: {e}")
            return False
    
    def find_mac_duplicates(self, addresses):
        """
        Trouve tous les doublons MAC dans une liste d'adresses
        
        API: Aucun (traitement local)
        Params: addresses (list[dict]) - Liste des adresses à analyser
        Returns: list[tuple] - Liste des paires (addr1, addr2) ayant la même MAC
        """
        duplicates = []
        processed_macs = set()
        
        try:
            for i, addr1 in enumerate(addresses):
                has_mac1, mac1, _ = self.has_mac_and_dhcp_profil(addr1)
                if not has_mac1 or mac1 in processed_macs:
                    continue
                
                duplicate_group = [addr1]
                
                # Chercher tous les doublons de cette MAC
                for j, addr2 in enumerate(addresses[i+1:], i+1):
                    has_mac2, mac2, _ = self.has_mac_and_dhcp_profil(addr2)
                    if has_mac2 and mac1 == mac2:
                        duplicate_group.append(addr2)
                
                # Si doublons trouvés, créer toutes les paires
                if len(duplicate_group) > 1:
                    processed_macs.add(mac1)
                    for k in range(len(duplicate_group)-1):
                        duplicates.append((duplicate_group[k], duplicate_group[k+1]))
                    logger.warning(f"Doublon MAC détecté: {mac1} ({len(duplicate_group)} adresses)")
            
            logger.info(f"Trouvé {len(duplicates)} paires de doublons MAC")
            return duplicates
            
        except Exception as e:
            logger.error(f"Erreur find_mac_duplicates: {e}")
            return []

    def find_hostname_duplicates(self, addresses):
        """
        Trouve tous les doublons hostname dans une liste d'adresses
        
        API: Aucun (traitement local)
        Params: addresses (list[dict]) - Liste des adresses à analyser
        Returns: list[tuple] - Liste des paires (addr1, addr2) ayant le même hostname
        """
        duplicates = []
        processed_hostnames = set()
        
        try:
            for i, addr1 in enumerate(addresses):
                hostname1 = addr1.get('hostname')
                if not hostname1 or hostname1.lower().strip() in processed_hostnames:
                    continue
                
                hostname1_clean = hostname1.lower().strip()
                duplicate_group = [addr1]
                
                # Chercher tous les doublons de ce hostname
                for j, addr2 in enumerate(addresses[i+1:], i+1):
                    hostname2 = addr2.get('hostname')
                    if hostname2 and hostname2.lower().strip() == hostname1_clean:
                        duplicate_group.append(addr2)
                
                # Si doublons trouvés, créer toutes les paires
                if len(duplicate_group) > 1:
                    processed_hostnames.add(hostname1_clean)
                    for k in range(len(duplicate_group)-1):
                        duplicates.append((duplicate_group[k], duplicate_group[k+1]))
                    logger.warning(f"Doublon hostname détecté: {hostname1_clean} ({len(duplicate_group)} adresses)")
            
            logger.info(f"Trouvé {len(duplicates)} paires de doublons hostname")
            return duplicates
            
        except Exception as e:
            logger.error(f"Erreur find_hostname_duplicates: {e}")
            return []

    def determine_most_recent(self, addr1, addr2):
        """
        Détermine l'adresse la plus récente entre deux (stratégies multiples)
        
        API: Potentiellement GET /addresses/{id}/changelog/ si nécessaire
        Params: addr1, addr2 (dict) - Deux adresses à comparer
        Returns: dict - L'adresse la plus récente (celle à supprimer)
        """
        try:
            # Stratégie 1: Comparer les dates d'édition
            edit_date1 = addr1.get('editDate')
            edit_date2 = addr2.get('editDate')
            
            # Si on n'a pas les dates, essayer de les récupérer depuis le changelog
            if not edit_date1:
                try:
                    changelog1 = self.get_address_changelog(addr1.get('id'))
                    if changelog1:
                        edit_date1 = changelog1[-1].get('date')
                except Exception:
                    pass
            
            if not edit_date2:
                try:
                    changelog2 = self.get_address_changelog(addr2.get('id'))
                    if changelog2:
                        edit_date2 = changelog2[-1].get('date')
                except Exception:
                    pass
            
            # Comparer les dates si disponibles
            if edit_date1 and edit_date2:
                if edit_date1 > edit_date2:
                    logger.debug(f"Stratégie date: {addr1.get('ip')} plus récent ({edit_date1} > {edit_date2})")
                    return addr1
                else:
                    logger.debug(f"Stratégie date: {addr2.get('ip')} plus récent ({edit_date2} >= {edit_date1})")
                    return addr2
            
            # Stratégie 2: Comparer les IDs (plus grand = plus récent)
            try:
                id1 = int(addr1.get('id', 0))
                id2 = int(addr2.get('id', 0))
                
                if id1 > id2:
                    logger.debug(f"Stratégie ID: {addr1.get('ip')} plus récent (ID {id1} > {id2})")
                    return addr1
                else:
                    logger.debug(f"Stratégie ID: {addr2.get('ip')} plus récent (ID {id2} >= {id1})")
                    return addr2
            except (ValueError, TypeError):
                pass
            
            # Stratégie 3: Dernier recours - retourner la première adresse
            logger.debug(f"Stratégie fallback: suppression de {addr1.get('ip')}")
            return addr1
            
        except Exception as e:
            logger.error(f"Erreur determine_most_recent: {e}")
            return addr1  # Fallback

    def remove_mac_from_address(self, address_id):
        """
        Supprime uniquement la MAC d'une adresse (garde le reste)
        
        API: PATCH /api/{app_id}/addresses/{id}/
        Params: address_id (str) - ID de l'adresse
        Returns: bool - True si suppression réussie
        """
        if not self._ensure_auth():
            return False
        
        try:
            payload = {"mac": ""}
            
            response = self.session.patch(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token},
                json=payload
            )
            
            if response.status_code == 200:
                # Gestion des réponses vides de phpIPAM
                if response.text.strip():
                    result = response.json()
                    if result.get("success", True):
                        logger.info(f"MAC supprimée avec succès pour adresse ID {address_id}")
                        return True
                else:
                    logger.info(f"MAC supprimée avec succès pour adresse ID {address_id} (réponse vide)")
                    return True
            
            logger.error(f"Échec suppression MAC pour adresse {address_id}: {response.status_code}")
            return False
            
        except Exception as e:
            logger.error(f"Erreur remove_mac_from_address {address_id}: {e}")
            return False

    def close(self):
        """Ferme la session HTTP"""
        if hasattr(self, 'session'):
            self.session.close()

    def __del__(self):
        """Destructeur"""
        self.close()