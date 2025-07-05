#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 ______  __  __  ______  __  ______  ______  __    __ 
/\  == \/\ \_\ \/\  == \/\ \/\  == \/\  __ \/\ "-./  \
\ \  _-/\ \  __ \ \  _-/\ \ \ \  _-/\ \  __ \ \ \-./\ \
 \ \_\   \ \_\ \_\ \_\   \ \_\ \_\   \ \_\ \_\ \_\ \ \_\
  \/_/    \/_/\/_/\/_/    \/_/\/_/    \/_/\/_/\/_/  \/_/
                                                       
Module phpIPAM API pour l'intégration phpIPAM-PowerDNS
Fonctions:
- Authentification à l'API phpIPAM
- Récupération et gestion des adresses IP
- Récupération des informations de sections et sous-réseaux

Auteur: Lecoq Alexis
Date: 06/05/25
Version: 1.1
"""

import requests
import base64
import logging
import importlib
from datetime import datetime, timedelta
import ipaddress

# Import explicite du module datetime standard
std_datetime = importlib.import_module('datetime')
datetime = std_datetime.datetime
timedelta = std_datetime.timedelta

logger = logging.getLogger("pphook")

class PhpIPAMAPI:
    """Classe pour interagir avec l'API phpIPAM - Optimisée pour intégration DNS"""
    
    def __init__(self, api_url, app_id, username, password, config=None):
        self.api_url = api_url.rstrip('/')
        self.app_id = app_id
        self.username = username
        self.password = password
        self.config = config
        self.token = None
        self.token_expires = datetime.now()

    def authenticate(self):
        """Authentification à l'API phpIPAM"""
        auth_url = f"{self.api_url}/{self.app_id}/user/"
        
        auth_header = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("utf-8")
        headers = {"Authorization": f"Basic {auth_header}"}
        
        try:
            response = requests.post(auth_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                self.token = data["data"]["token"]
                
                # Expiration dans 1 heure 
                self.token_expires = datetime.now() + timedelta(hours=1)   
                
                logger.info(f"Authentification réussie à phpIPAM")
                return True
            else:
                logger.error(f"Échec d'authentification: {data.get('message', 'Erreur inconnue')}")
                return False
        except Exception as e:
            logger.error(f"Erreur lors de l'authentification à phpIPAM: {str(e)}")
            return False
    
    def ensure_auth(self):
        """S'assure que nous avons un token valide"""
        if self.token is None or datetime.now() >= self.token_expires:
            return self.authenticate()
        return True
    
    def get_addresses(self, since=None, hostname_filter=None, include_inactive=False):
        """Récupère les adresses IP depuis phpIPAM"""
        if not self.ensure_auth():
            return []

        # Format de l'URL pour récupérer toutes les adresses
        addresses_url = f"{self.api_url}/{self.app_id}/addresses/"

        headers = {"token": self.token}
        params = {}

        try:
            response = requests.get(addresses_url, headers=headers, params=params)
            response.raise_for_status()

            data = response.json()
            if data["success"]:
                addresses = data["data"]
                filtered_addresses = []
                
                # Convertir since au format string si c'est un datetime
                since_str = None
                if since and isinstance(since, datetime):
                    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

                for addr in addresses:
                    # Vérifier si l'adresse est active
                    if not include_inactive and addr.get("state") == "0":
                        continue
                        
                    # Filtrer par date si nécessaire
                    if since and "editDate" in addr:
                        # Récupérer la date d'édition avec vérification de validité
                        edit_date = addr.get("editDate")
                        
                        # Si pas de date d'édition ou vide, inclure l'adresse (comportement sécurisé)
                        if not edit_date or str(edit_date).strip() == "":
                            logger.warning(f"Date d'édition manquante pour l'adresse {addr.get('ip', 'Unknown')} - inclusion par défaut")
                            # Pas de continue ici - on laisse l'adresse passer
                        else:
                            # Convertir since en string si c'est un datetime
                            if isinstance(since, datetime):
                                since_str = since.strftime("%Y-%m-%d %H:%M:%S")
                            else:
                                since_str = str(since)
                                
                            # Comparer les strings directement - maintenant sécurisé
                            try:
                                if edit_date <= since_str:
                                    continue
                            except TypeError as e:
                                # En cas d'erreur de comparaison, logger et inclure l'adresse
                                logger.warning(f"Erreur de comparaison de date pour l'adresse {addr.get('ip', 'Unknown')}: {e} - inclusion par défaut")
                            
                    # Filtrer par hostname si nécessaire
                    if hostname_filter and hostname_filter.lower() not in addr.get("hostname", "").lower():
                        continue
                        
                    filtered_addresses.append(addr)

                return filtered_addresses
            else:
                logger.error(f"Échec de récupération des adresses: {data.get('message', 'Erreur inconnue')}")
                return []
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des adresses: {str(e)}")
            return []

    def get_subnets(self):
        """Récupère tous les subnets depuis phpIPAM"""
        if not self.ensure_auth():
            return []

        subnets_url = f"{self.api_url}/{self.app_id}/subnets/"
        headers = {"token": self.token}
        
        try:
            response = requests.get(subnets_url, headers=headers)
            response.raise_for_status()

            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.error(f"Échec de récupération des subnets: {data.get('message', 'Erreur inconnue')}")
                return []
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des subnets: {str(e)}")
            return []   
  
    def get_subnet_details(self, subnet_id):
        """Récupère les détails d'un sous-réseau spécifique"""
        if not self.ensure_auth():
            return None
            
        subnet_url = f"{self.api_url}/{self.app_id}/subnets/{subnet_id}/"
        
        headers = {"token": self.token}
        
        try:
            response = requests.get(subnet_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.error(f"Échec de récupération des détails du sous-réseau {subnet_id}: {data.get('message', 'Erreur inconnue')}")
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des détails du sous-réseau {subnet_id}: {str(e)}")
            return None
                                 
    def get_section_details(self, section_id):
        """Récupère les détails d'une section"""
        if not self.ensure_auth():
            return None
            
        section_url = f"{self.api_url}/{self.app_id}/sections/{section_id}/"
        
        headers = {"token": self.token}
        
        try:
            response = requests.get(section_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.error(f"Échec de récupération des détails de la section {section_id}: {data.get('message', 'Erreur inconnue')}")
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des détails de la section {section_id}: {str(e)}")
            return None
        
    def get_changelog_entries(self, limit=100):
        """
        Récupère les entrées récentes du changelog
        
        Args:
            limit (int): Nombre maximum d'entrées à récupérer
            
        Returns:
            list: Liste des entrées du changelog
        """
        if not self.ensure_auth():
            return []
            
        changelog_url = f"{self.api_url}/{self.app_id}/tools/changelog/"
        
        headers = {"token": self.token}
        params = {"limit": limit}
        
        try:
            response = requests.get(changelog_url, headers=headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.error(f"Échec de récupération du changelog: {data.get('message', 'Erreur inconnue')}")
                return []
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du changelog: {str(e)}")
            return []

    def get_address_changelog(self, address_id):
        """
        Récupère l'historique des modifications pour une adresse spécifique
        
        Args:
            address_id (str): ID de l'adresse
            
        Returns:
            list: Liste des modifications pour cette adresse
        """
        if not self.ensure_auth():
            return []
            
        changelog_url = f"{self.api_url}/{self.app_id}/addresses/{address_id}/changelog/"
        
        headers = {"token": self.token}
        
        try:
            response = requests.get(changelog_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.error(f"Échec de récupération de l'historique de l'adresse {address_id}: {data.get('message', 'Erreur inconnue')}")
                return []
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique de l'adresse {address_id}: {str(e)}")
            return []
        
    def get_addresses_with_mac_and_dhcp_profil(self):
        """
        Récupère toutes les adresses avec MAC non nulle et custom_DHCP_Profil = 'infra' ou 'lise'
    
        Returns:
            list: Liste des adresses avec MAC et profil DHCP, chaque élément contient:
                - id, ip, hostname, mac, editDate, subnetId, dhcp_profil
        """
        try:
            # Récupérer toutes les adresses
            all_addresses = self.get_addresses(include_inactive=False)
        
            if not all_addresses:
                logger.info("Aucune adresse trouvée dans phpIPAM")
                return []

            # Filtrer les adresses avec MAC non nulle et custom_DHCP_Profil valide
            filtered_addresses = []
            for address in all_addresses:
                # Vérifier si MAC n'est pas nulle
                mac_value = address.get('mac')
                if mac_value is None or mac_value == '' or str(mac_value).strip() == '':
                    continue

                # Vérifier custom_DHCP_Profil (CHANGEMENT ICI)
                dhcp_profil = address.get('custom_DHCP_Profil')
                if dhcp_profil is None:
                    continue

                # Conversion sûre en string et vérification des valeurs
                try:
                    dhcp_profil_str = str(dhcp_profil).lower().strip()
                    if dhcp_profil_str not in ['infra', 'lise']:
                        continue
                except Exception as e:
                    logger.warning(f"Erreur conversion custom_DHCP_Profil pour adresse {address.get('id')}: {e}")
                    continue

                # Ajouter l'adresse avec toutes les infos
                try:
                    filtered_addresses.append({
                        'id': address.get('id'),
                        'ip': address.get('ip'),
                        'hostname': address.get('hostname', 'Non défini'),
                        'mac': str(mac_value).lower().strip(),  # Normaliser la MAC
                        'editDate': address.get('editDate', 'Non défini'),
                        'subnetId': address.get('subnetId'),
                        'dhcp_profil': dhcp_profil_str  # Ajouter le profil DHCP
                    })
                except Exception as e:
                    logger.warning(f"Erreur traitement adresse {address.get('id')}: {e}")
                    continue

            logger.info(f"Trouvé {len(filtered_addresses)} adresses avec MAC et custom_DHCP_Profil (infra/lise)")
        
            # Statistiques par profil
            infra_count = sum(1 for addr in filtered_addresses if addr['dhcp_profil'] == 'infra')
            lise_count = sum(1 for addr in filtered_addresses if addr['dhcp_profil'] == 'lise')
            logger.info(f"Répartition: {infra_count} infra, {lise_count} lise")
        
            return filtered_addresses

        except Exception as e:
            logger.error(f"Erreur lors de la récupération des adresses DHCP: {str(e)}")
            return []

    def remove_mac_from_address(self, address_id):
        """
        Supprime la MAC d'une adresse dans phpIPAM
        
        Args:
            phpipam (PhpIPAMAPI): Instance de l'API phpIPAM
            address_id (str): ID de l'adresse
            
        Returns:
            bool: True si la suppression a réussi, False sinon
        """
        try:
            # URL pour modifier une adresse
            address_url = f"{self.api_url}/{self.app_id}/addresses/{address_id}/"
            
            headers = {"token": self.token}
            data = {"mac": ""}  # Vider le champ MAC
            
            response = requests.patch(address_url, headers=headers, data=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    logger.info(f"MAC supprimée avec succès pour l'adresse ID {address_id}")
                    return True
                else:
                    logger.error(f"Échec suppression MAC pour adresse {address_id}: {result.get('message', 'Erreur inconnue')}")
                    return False
            else:
                logger.error(f"Erreur HTTP lors de la suppression MAC: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Exception lors de la suppression MAC pour adresse {address_id}: {str(e)}")
            return False

    def get_domain_for_subnet(self, subnet_id):
        """Détermine le domaine associé à un sous-réseau"""
        subnet = self.get_subnet_details(subnet_id)
        if not subnet:
            return None

        # Vérifier si un domaine est configuré explicitement pour ce sous-réseau
        if "custom_dnsdomain" in subnet and subnet["custom_dnsdomain"]:
            return subnet["custom_dnsdomain"]

        # Vérifier si un domaine est configuré pour la section parente
        if "sectionId" in subnet:
            section = self.get_section_details(subnet["sectionId"])
            if section and "custom_dnsdomain" in section and section["custom_dnsdomain"]:
                return section["custom_dnsdomain"]

        # Utiliser le domaine par défaut défini dans la configuration
        return self.config.get('default', 'domain', fallback='interne.exemple.com') if self.config else 'interne.exemple.com'

    def build_fqdn(self, hostname, domain):
        """Construit un FQDN à partir d'un hostname et d'un domaine"""
        # Si le hostname contient déjà des points, c'est peut-être déjà un FQDN
        if "." in hostname:
            # Vérifier si le hostname se termine par le domaine
            if hostname.lower().endswith(domain.lower()):
                return hostname
            else:
                # C'est un sous-domaine mais pas dans le domaine cible
                return f"{hostname}.{domain}"
        else:
            # Simple hostname, ajouter le domaine
            return f"{hostname}.{domain}"

    def validate_mac_duplicates(self, notification_callback=None):
        """
        Valide les adresses MAC pour détecter les doublons
        VERSION MODIFIÉE : Supprime la MAC de l'adresse la plus récente
        
        Args:
            notification_callback (callable): Fonction de callback pour les notifications
                                            Doit accepter un dict avec les infos du doublon
            
        Returns:
            bool: True si la validation s'est bien passée, False sinon
        """
        logger.info("Début de la validation des doublons MAC")
        
        try:
            # Récupérer les adresses avec MAC et tag infra
            addresses_with_mac = self.get_addresses_with_mac_and_dhcp_profil()
            
            if len(addresses_with_mac) < 2:
                logger.info("Pas assez d'adresses avec MAC pour détecter des doublons")
                return True
            
            # Extraire les MACs
            macs = [addr['mac'] for addr in addresses_with_mac]
            
            # Algorithme de détection de doublons
            duplicates_found = []
            processed_macs = set()  # Pour éviter de traiter plusieurs fois la même MAC
            
            for i in range(len(macs) - 1):
                cursor = macs[i]
                
                # Skip si cette MAC a déjà été traitée
                if cursor in processed_macs:
                    continue
                    
                duplicate_addresses = [addresses_with_mac[i]]  # Inclure l'adresse courante
                
                # Chercher tous les doublons de cette MAC
                for j in range(i + 1, len(macs)):
                    if macs[j] == cursor:
                        duplicate_addresses.append(addresses_with_mac[j])
                
                # Si on a trouvé des doublons
                if len(duplicate_addresses) > 1:
                    processed_macs.add(cursor)
                    
                    # Trier par date d'édition pour trouver la plus récente
                    duplicate_addresses.sort(key=lambda x: x['editDate'], reverse=True)
                    most_recent = duplicate_addresses[-1]  # La plus récente
                    
                    logger.warning(f"Doublon MAC détecté: {cursor}")
                    for addr in duplicate_addresses:
                        logger.warning(f"  - IP: {addr['ip']} ({addr['hostname']}) - Modifié: {addr['editDate']}")
                    
                    # Supprimer la MAC de l'adresse la plus récente
                    logger.info(f"Suppression de la MAC pour l'adresse la plus récente: {most_recent['ip']}")
                    success = self.remove_mac_from_address(most_recent['id'])
                    
                    if success:
                        logger.info(f"MAC supprimée avec succès pour l'adresse {most_recent['ip']}")
                        
                        # Notifier après suppression si callback fourni
                        if notification_callback:
                            duplicate_info = {
                                'mac': cursor,
                                'addresses': duplicate_addresses,
                                'removed_from': most_recent,
                                'api_url': self.api_url  # Ajout de l'URL API pour construire les liens
                            }
                            notification_callback(duplicate_info)
                        
                        duplicates_found.append({
                            'mac': cursor,
                            'addresses': duplicate_addresses,
                            'removed_from': most_recent
                        })
                    else:
                        logger.error(f"Échec de suppression de la MAC pour l'adresse {most_recent['ip']}")
            
            if duplicates_found:
                logger.info(f"Validation MAC terminée: {len(duplicates_found)} doublons traités")
            else:
                logger.info("Validation MAC terminée: aucun doublon détecté")
                
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation des doublons MAC: {str(e)}")
            return False
          
    def validate_hostname_duplicate(self, ip):
        """Vérifie s'il y a des duplications d'hostname pour une IP donnée"""
        try:
            all_addresses = self.get_addresses(include_inactive=False)
            target_hostname = None
            
            # Trouver le hostname de l'IP
            for address in all_addresses:
                if address.get('ip') == ip and address.get('hostname'):
                    hostname_value = address.get('hostname')
                    # Fix: vérifier que hostname n'est pas None
                    if hostname_value is not None:
                        target_hostname = hostname_value.lower().strip()
                        break
            
            if not target_hostname:
                return False, None
            
            # Trouver la première occurrence de duplication (différente de l'IP donnée)
            for addr in all_addresses:
                if addr.get('ip') != ip:
                    # Fix: sécuriser le .lower() avec vérification None
                    compare_hostname = addr.get('hostname')
                    if compare_hostname is not None and compare_hostname.lower().strip() == target_hostname:
                        return True, addr
            
            return False, None
            
        except Exception as e:
            logger.error(f"Erreur vérification doublons {ip}: {str(e)}")
            return False, None

    def delete_address(self, ip):
        """Supprime une adresse IP de phpIPAM"""
        try:
            if not self.ensure_auth():
                return False
            
            # Trouver l'ID de l'IP
            all_addresses = self.get_addresses(include_inactive=True)
            address_id = next((addr.get('id') for addr in all_addresses if addr.get('ip') == ip), None)
            
            if not address_id:
                return False
            
            # Supprimer
            url = f"{self.api_url}/{self.app_id}/addresses/{address_id}/"
            response = requests.delete(url, headers={"token": self.token})
            
            return response.status_code == 200 and response.json().get("success", False)
            
        except Exception as e:
            logger.error(f"Erreur suppression {ip}: {str(e)}")
            return False
    
    def get_all_users(self):
        """Récupère tous les utilisateurs"""
        if not self.ensure_auth():
            return []
        
        try:
            response = requests.get(f"{self.api_url}/{self.app_id}/user/all/", headers={"token": self.token})
            return response.json()["data"]
        except:
            return []

    def get_user_email_from_changelog(self, address_id):
        """
        Récupère l'email de l'utilisateur depuis le changelog
        Returns: (email, real_name) ou (None, None)
        """
        try:
            # Récupérer changelog
            changelog = self.get_address_changelog(address_id)
            real_name = changelog[-1]["user"]
            
            # Récupérer tous les users
            users = self.get_all_users()
            
            # Trouver l'email
            for user in users:
                if user["real_name"] == real_name:
                    return user["email"], real_name
            
            return None, real_name
        except:
            return None, None
