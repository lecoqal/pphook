#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module phpIPAM API pour l'intégration phpIPAM-PowerDNS

Auteur: Lecoq Alexis
Date: 06/05/25
Version: 1.0
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
        self.api_url = api_url.rstrip("/")
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
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST", "PATCH"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)

        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.timeout = (5, 30)

        session.headers.update(
            {
                "User-Agent": "PPHOOK/2.0",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

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
                f"{self.api_url}/{self.app_id}/addresses/", headers={"token": self.token}
            )
            response.raise_for_status()

            data = response.json()
            if not data["success"]:
                logger.error(f"Erreur get_addresses: {data.get('message')}")
                return []

            addresses = data["data"]
            filtered = []

            since_str = since.strftime("%Y-%m-%d %H:%M:%S") if since else None
            addresses_without_editdate = 0

            for addr in addresses:
                # Filtrer inactives
                if addr.get("state") == "0":
                    continue

                # 1) LOG ADRESSES SANS EDITDATE
                edit_date = addr.get("editDate")
                if not edit_date or str(edit_date).strip() == "":
                    addresses_without_editdate += 1
                    logger.info(f"Adresse sans editDate: {addr.get('ip')} ({addr.get('hostname')})")

                # 2) INCLURE TOUTES LES ADRESSES (même sans editDate)
                if since_str:
                    # Si pas d'editDate, on inclut quand même (sera traitée)
                    if edit_date and edit_date <= since_str:
                        continue

                filtered.append(addr)

            # Log récapitulatif
            if addresses_without_editdate > 0:
                logger.info(
                    f"Trouvé {addresses_without_editdate} adresses sans editDate - incluses dans le traitement"
                )

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
                headers={"token": self.token},
            )
            response.raise_for_status()

            data = response.json()
            if data["success"]:
                return data["data"]
            else:
                logger.info(f"Pas de changelog pour adresse {address_id}")
                return []

        except Exception as e:
            logger.info(f"Erreur changelog adresse {address_id}: {e}")
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
                f"{self.api_url}/{self.app_id}/user/all/", headers={"token": self.token}
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
            mac_value = address.get("mac")
            if not mac_value or str(mac_value).strip() == "":
                return False, None, None

            # Normaliser MAC
            mac_clean = str(mac_value).lower().strip()

            # Vérifier profil DHCP
            dhcp_profil = address.get("custom_DHCP_Profil")
            if not dhcp_profil:
                return False, mac_clean, None

            dhcp_profil_clean = str(dhcp_profil).lower().strip()
            if dhcp_profil_clean not in ["infra", "lise"]:
                return False, mac_clean, dhcp_profil_clean

            return True, mac_clean, dhcp_profil_clean

        except Exception as e:
            logger.warning(f"Erreur validation MAC/DHCP pour adresse {address.get('id')}: {e}")
            return False, None, None

    def delete_address(self, ip, addresses=None):
        """
        Supprime une adresse par son IP

        API: DELETE /api/{app_id}/addresses/{id}/
        Params:
            ip (str) - Adresse IP à supprimer
            addresses (list) - Liste des adresses (évite un appel API)
        Returns: bool - True si suppression réussie
        """
        if not self._ensure_auth():
            return False

        try:
            address_id = None

            # Si on a la liste des adresses, l'utiliser
            if addresses:
                for addr in addresses:
                    if addr.get("ip") == ip:
                        address_id = addr.get("id")
                        break
            else:
                # Fallback : chercher dans toutes les adresses (ancien comportement)
                all_addresses = self.get_addresses()
                for addr in all_addresses:
                    if addr.get("ip") == ip:
                        address_id = addr.get("id")
                        break

            if not address_id:
                logger.warning(f"Adresse {ip} non trouvée pour suppression")
                return False

            # Supprimer l'adresse
            response = self.session.delete(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token},
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

    def find_hostname_duplicates(self, addresses):
        """
        Trouve tous les doublons hostname dans une liste d'adresses - VERSION CORRIGÉE

        API: Aucun (traitement local)
        Params: addresses (list[dict]) - Liste des adresses à analyser
        Returns: dict - {hostname: [list_addresses]} pour chaque hostname dupliqué
        """
        hostname_groups = {}
        duplicates = {}

        try:
            # Grouper les adresses par hostname
            for addr in addresses:
                hostname = addr.get("hostname")
                if not hostname:
                    continue

                hostname_clean = hostname.lower().strip()
                if hostname_clean not in hostname_groups:
                    hostname_groups[hostname_clean] = []
                hostname_groups[hostname_clean].append(addr)

            # Identifier les groupes avec doublons
            for hostname_clean, group in hostname_groups.items():
                if len(group) > 1:
                    duplicates[hostname_clean] = group

                    logger.warning(
                        f"Doublon hostname détecté: {hostname_clean} ({len(group)} adresses)"
                    )

                    # Afficher toutes les adresses dupliquées
                    for idx, addr in enumerate(group, 1):
                        logger.info(
                            f"  Adresse {idx}: {addr.get('ip')} (ID: {addr.get('id')}, editDate: {addr.get('editDate')})"
                        )

            if duplicates:
                logger.info(
                    f"Trouvé {len(duplicates)} hostnames dupliqués - traitement en cours..."
                )
            else:
                logger.info("Aucun doublon hostname détecté")

            return duplicates

        except Exception as e:
            logger.error(f"Erreur find_hostname_duplicates: {e}")
            return {}  # IMPORTANT: Retourner un dict vide, pas une liste

    def determine_oldest_to_keep(self, addresses_list):
        """
        Détermine l'adresse la plus ancienne à garder (ne pas supprimer)

        Params: addresses_list (list) - Liste des adresses dupliquées
        Returns: dict - L'adresse à garder (la plus ancienne)
        """
        if not addresses_list:
            return None

        # Si une seule adresse, la garder
        if len(addresses_list) == 1:
            return addresses_list[0]

        oldest_addr = addresses_list[0]

        for addr in addresses_list[1:]:
            # Logique directe : comparer editDate puis ID
            edit_date1 = oldest_addr.get("editDate")
            edit_date2 = addr.get("editDate")

            # Si les deux ont editDate, comparer
            if edit_date1 and edit_date2 and edit_date1 != "None" and edit_date2 != "None":
                if edit_date2 < edit_date1:  # addr est plus ancien
                    oldest_addr = addr
            else:
                # Fallback sur ID (plus petit = plus ancien)
                try:
                    id1 = int(oldest_addr.get("id", 999999))
                    id2 = int(addr.get("id", 999999))
                    if id2 < id1:  # addr est plus ancien
                        oldest_addr = addr
                except:
                    pass

        return oldest_addr

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
                json=payload,
            )

            if response.status_code == 200:
                # Gestion des réponses vides de phpIPAM
                if response.text.strip():
                    result = response.json()
                    if result.get("success", True):
                        logger.info(f"MAC supprimée avec succès pour adresse ID {address_id}")
                        return True
                else:
                    logger.info(
                        f"MAC supprimée avec succès pour adresse ID {address_id} (réponse vide)"
                    )
                    return True

            logger.error(f"Échec suppression MAC pour adresse {address_id}: {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"Erreur remove_mac_from_address {address_id}: {e}")
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
                logger.debug(f"Adresse {addr1.get('ip')}: has_mac={has_mac1}, mac={mac1}")
                if not has_mac1 or mac1 in processed_macs:
                    continue

                duplicate_group = [addr1]

                # Chercher tous les doublons de cette MAC
                for j, addr2 in enumerate(addresses[i + 1 :], i + 1):
                    has_mac2, mac2, _ = self.has_mac_and_dhcp_profil(addr2)
                    if has_mac2 and mac1 == mac2:
                        duplicate_group.append(addr2)

                # Si doublons trouvés, créer toutes les paires
                if len(duplicate_group) > 1:
                    processed_macs.add(mac1)
                    for k in range(len(duplicate_group) - 1):
                        duplicates.append((duplicate_group[k], duplicate_group[k + 1]))
                    logger.warning(f"Doublon MAC détecté: {mac1} ({len(duplicate_group)} adresses)")

            logger.info(f"Trouvé {len(duplicates)} paires de doublons MAC")
            return duplicates

        except Exception as e:
            logger.error(f"Erreur find_mac_duplicates: {e}")
            return []

    def force_editdate_update(self, address_id):
        """
        Force la mise à jour de l'editDate avec vérification finale
        """
        if not self._ensure_auth():
            return False

        try:
            # Étape 1: Récupérer l'adresse actuelle
            response = self.session.get(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token},
            )

            if response.status_code != 200:
                logger.error(f"Impossible de récupérer l'adresse {address_id}")
                return False

            data = response.json()
            if not data.get("success"):
                logger.error(f"Erreur API lors de la récupération de l'adresse {address_id}")
                return False

            # Récupérer la description actuelle (ou chaîne vide si None)
            current_description = data["data"].get("description") or ""
            current_editdate = data["data"].get("editDate")

            # Étape 2: Ajouter un espace
            response = self.session.patch(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token},
                json={"description": current_description + " "},
            )

            if response.status_code != 200:
                logger.error(f"Échec ajout espace pour adresse {address_id}")
                return False

            # Étape 3: Enlever l'espace (retour à l'état original)
            response = self.session.patch(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token},
                json={"description": current_description},
            )

            if response.status_code != 200:
                logger.error(f"Échec suppression espace pour adresse {address_id}")
                return False

            # Étape 4: VÉRIFICATION FINALE - Récupérer l'adresse pour vérifier editDate
            verify_response = self.session.get(
                f"{self.api_url}/{self.app_id}/addresses/{address_id}/",
                headers={"token": self.token},
            )

            if verify_response.status_code == 200:
                verify_data = verify_response.json()
                if verify_data.get("success"):
                    new_editdate = verify_data["data"].get("editDate")

                    # Vérifier que l'editDate a réellement changé
                    if new_editdate and new_editdate != "None" and new_editdate != current_editdate:
                        logger.info(
                            f"EditDate mise à jour avec succès pour adresse {address_id}: {current_editdate} → {new_editdate}"
                        )
                        return True
                    else:
                        logger.info(
                            f"EditDate non modifiée pour adresse {address_id} (reste: {new_editdate})"
                        )
                        return False

            logger.error(f"Impossible de vérifier editDate pour adresse {address_id}")
            return False

        except Exception as e:
            logger.error(f"Erreur force_editdate_update {address_id}: {e}")
            return False

    def get_user_email_from_changelog(self, changelog, users, generic_email):
        """
        Récupère les infos utilisateur depuis un changelog déjà récupéré

        Args:
            changelog (list): Changelog de l'adresse
            users (list): Liste des utilisateurs phpIPAM
            generic_email (str): Email générique de fallback

        Returns:
            tuple: (user_email, username, use_generic_email)
        """
        # Essayer d'abord de récupérer l'email utilisateur depuis le changelog
        if changelog and len(changelog) > 0:
            try:
                real_name = changelog[-1]["user"]
                # Trouver l'email dans la liste des users
                for user in users:
                    if user["real_name"] == real_name:
                        return user["email"], real_name, False

                # User trouvé dans changelog mais pas dans la liste des users
                logger.info(
                    f"Utilisateur '{real_name}' trouvé dans changelog mais pas dans la liste des users"
                )

            except Exception as e:
                logger.info(f"Erreur extraction utilisateur depuis changelog: {e}")

        if generic_email and generic_email.strip():
            username = (
                changelog[-1]["user"] if changelog and len(changelog) > 0 else "Utilisateur inconnu"
            )
            logger.info(f"Utilisation email générique pour utilisateur: {username}")
            return generic_email, username, True

        # Aucune solution trouvée
        logger.warning("Aucun email disponible (ni utilisateur ni générique)")
        return None, None, False

    def get_changelog_summary(self, changelog, use_generic_email):
        """
        Récupère les détails depuis un changelog déjà récupéré

        Args:
            changelog (list): Changelog de l'adresse
            use_generic_email (bool): Si True, retourne des valeurs par défaut

        Returns:
            tuple: (edit_date, action)
        """
        if use_generic_email or not changelog or len(changelog) == 0:
            return "Date inconnue", "Action inconnue"

        try:
            last_change = changelog[-1]
            return last_change.get("date", "Date inconnue"), last_change.get(
                "action", "Action inconnue"
            )
        except Exception:
            return "Date inconnue", "Action inconnue"

    def clean_mac_duplicates(self, addresses):
        """
        Nettoie les doublons MAC dans une liste d'adresses

        Args:
            addresses (list): Liste des adresses à analyser

        Returns:
            tuple: (cleaned_count, processed_items, updated_addresses)
        """
        logger.info("=== Début nettoyage doublons MAC ===")

        cleaned_count = 0
        processed_items = []
        updated_addresses = addresses.copy()

        try:
            # 1. Trouver les doublons MAC
            duplicates = self.find_mac_duplicates(addresses)
            logger.info(f"Trouvé {len(duplicates)} paires de doublons MAC")

            # 2. Traiter chaque paire de doublons
            for addr1, addr2 in duplicates:
                try:
                    # Déterminer l'adresse à garder (la plus ancienne)
                    address_to_keep = self.determine_oldest_to_keep([addr1, addr2])
                    address_to_remove = addr1 if address_to_keep == addr2 else addr2

                    logger.info(
                        f"Doublon MAC: suppression {address_to_remove.get('ip')} ({address_to_remove.get('hostname')}), conservation {address_to_keep.get('ip')}"
                    )

                    # === RÉCUPÉRER LE CHANGELOG AVANT SUPPRESSION ===
                    changelog = self.get_address_changelog(address_to_remove.get("id"))

                    # 3. Supprimer la MAC de l'adresse dupliquée
                    if self.remove_mac_from_address(address_to_remove.get("id")):
                        cleaned_count += 1

                        # Préparer les infos pour notification
                        processed_items.append(
                            {
                                "address": address_to_remove,
                                "changelog": changelog,
                                "action": "mac_removed",
                                "duplicate_info": {
                                    "mac": address_to_remove.get("mac"),
                                    "kept_address": address_to_keep,
                                },
                            }
                        )

                        logger.info(f"MAC supprimée avec succès pour {address_to_remove.get('ip')}")
                    else:
                        logger.error(f"Échec suppression MAC pour {address_to_remove.get('ip')}")

                except Exception as e:
                    logger.error(f"Erreur lors du traitement doublon MAC: {e}")

            logger.info(f"Nettoyage MAC terminé: {cleaned_count} éléments traités")
            return cleaned_count, processed_items, updated_addresses

        except Exception as e:
            logger.error(f"Erreur générale lors du nettoyage MAC: {e}")
            return 0, [], addresses

    def clean_hostname_duplicates(self, addresses, powerdns, zones):
        """
        Nettoie les doublons hostname dans une liste d'adresses

        Args:
            addresses (list): Liste des adresses à analyser
            powerdns: Instance API PowerDNS pour nettoyage DNS
            zones: Liste des zones DNS

        Returns:
            tuple: (cleaned_count, processed_items, updated_addresses)
        """
        logger.info("=== Début nettoyage doublons HOSTNAME ===")

        cleaned_count = 0
        processed_items = []
        updated_addresses = addresses.copy()

        try:
            # 1. Trouver les doublons hostname
            duplicates = self.find_hostname_duplicates(addresses)
            logger.info(f"Trouvé {len(duplicates)} hostnames dupliqués")

            # 2. Traiter chaque groupe de doublons
            for hostname, duplicate_addresses in duplicates.items():
                try:
                    # Déterminer l'adresse à garder (la plus ancienne)
                    address_to_keep = self.determine_oldest_to_keep(duplicate_addresses)

                    # Créer la liste des adresses à supprimer
                    addresses_to_delete = duplicate_addresses.copy()
                    addresses_to_delete.remove(address_to_keep)

                    # Logs groupés
                    ips_to_delete = [addr.get("ip") for addr in addresses_to_delete]
                    logger.info(f"Doublon hostname: {hostname}")
                    logger.info(f"→ Suppression adresses: {', '.join(ips_to_delete)}")
                    logger.info(
                        f"→ Conservation adresse: {address_to_keep.get('ip')} (la plus ancienne)"
                    )

                    # 3. Supprimer chaque adresse dupliquée
                    for addr in addresses_to_delete:
                        ip = addr.get("ip")

                        try:
                            # === RÉCUPÉRER EMAIL AVANT SUPPRESSION ===
                            changelog = self.get_address_changelog(addr.get("id"))

                            # === SUPPRIMER SEULEMENT L'ADRESSE (pas les DNS) ===
                            if self.delete_address(ip, updated_addresses):
                                cleaned_count += 1
                                # Retirer de la liste
                                updated_addresses = [
                                    a for a in updated_addresses if a.get("ip") != ip
                                ]

                                # Préparer les infos pour notification
                                processed_items.append(
                                    {
                                        "address": addr,
                                        "changelog": changelog,
                                        "action": "address_deleted",
                                        "duplicate_info": {
                                            "hostname": hostname,
                                            "kept_address": address_to_keep,
                                        },
                                    }
                                )

                                logger.info(f"Adresse {ip} supprimée avec succès")
                            else:
                                logger.error(f"Échec suppression adresse {ip}")

                        except Exception as e:
                            logger.error(f"Erreur suppression adresse {ip}: {e}")

                except Exception as e:
                    logger.error(f"Erreur lors du traitement doublon hostname {hostname}: {e}")

            logger.info(f"Nettoyage HOSTNAME terminé: {cleaned_count} éléments traités")
            return cleaned_count, processed_items, updated_addresses

        except Exception as e:
            logger.error(f"Erreur générale lors du nettoyage hostname: {e}")
            return 0, [], addresses

    def close(self):
        """Ferme la session HTTP"""
        if hasattr(self, "session"):
            self.session.close()

    def __del__(self):
        """Destructeur"""
        self.close()
