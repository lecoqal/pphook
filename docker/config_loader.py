#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration loader pour PPHOOK avec Docker Secrets
Remplace le système GPG par la lecture des secrets Docker

Auteur: Adaptation Docker PPHOOK
Version: 1.0
"""

import os
import configparser
import logging

logger = logging.getLogger("pphook")

class DockerSecretsConfigLoader:
    """Charge la configuration depuis les Docker Secrets"""
    
    def __init__(self, secrets_path="/run/secrets"):
        self.secrets_path = secrets_path
        
    def read_secret(self, secret_name):
        """Lit un secret Docker"""
        secret_file = os.path.join(self.secrets_path, secret_name)
        try:
            if os.path.exists(secret_file):
                with open(secret_file, 'r') as f:
                    return f.read().strip()
            else:
                logger.warning(f"Secret {secret_name} non trouvé")
                return None
        except Exception as e:
            logger.error(f"Erreur lecture secret {secret_name}: {e}")
            return None
    
    def create_config_ini(self, output_file="/opt/pphook/config.ini"):
        """Crée le fichier config.ini à partir des secrets Docker"""
        
        # Mapping secrets vers variables config
        secrets_mapping = {
            # Section [phpipam]
            'phpipam_url': ('phpipam', 'api_url'),
            'phpipam_app_id': ('phpipam', 'app_id'),
            'phpipam_username': ('phpipam', 'username'),
            'phpipam_password': ('phpipam', 'password'),
            
            # Section [powerdns]
            'powerdns_url': ('powerdns', 'api_url'),
            'powerdns_api_key': ('powerdns', 'api_key'),
            
            # Section [email]
            'smtp_server': ('email', 'smtp_server'),
            'smtp_port': ('email', 'smtp_port'),
            'email_from': ('email', 'from'),
            'email_to': ('email', 'to'),
            'generic_email': ('email', 'generic_email'),
            
            # Section [validation]
            'hostname_pattern': ('validation', 'hostname_pattern'),
            'max_hostname_length': ('validation', 'max_hostname_length'),
            
            # Section [script]
            'check_interval': ('script', 'check_interval'),
        }
        
        # Valeurs par défaut
        defaults = {
            ('powerdns', 'server'): 'localhost',
            ('email', 'smtp_port'): '25',
            ('email', 'use_tls'): 'False',
            ('validation', 'hostname_pattern'): '^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$',
            ('validation', 'max_hostname_length'): '63',
            ('script', 'check_interval'): '60',
            ('script', 'last_check_file'): '/var/lib/pphook/last_check',
            ('default', 'domain'): 'local',
        }
        
        # Créer le parser de configuration
        config = configparser.ConfigParser()
        
        # Ajouter les sections
        sections = set()
        for _, (section, _) in secrets_mapping.items():
            sections.add(section)
        for section, _ in defaults.keys():
            sections.add(section)
            
        for section in sections:
            config.add_section(section)
        
        # Lire les secrets et remplir la config
        for secret_name, (section, key) in secrets_mapping.items():
            value = self.read_secret(secret_name)
            if value:
                config.set(section, key, value)
            else:
                logger.warning(f"Secret manquant: {secret_name}")
        
        # Ajouter les valeurs par défaut
        for (section, key), value in defaults.items():
            if not config.has_option(section, key):
                config.set(section, key, value)
        
        # Écrire le fichier de configuration
        try:
            with open(output_file, 'w') as f:
                config.write(f)
            logger.info(f"Configuration créée: {output_file}")
            return True
        except Exception as e:
            logger.error(f"Erreur écriture config: {e}")
            return False

def load_config_from_docker_secrets():
    """Fonction principale pour charger la configuration"""
    loader = DockerSecretsConfigLoader()
    
    # Créer le config.ini depuis les secrets
    if loader.create_config_ini():
        # Charger la configuration avec configparser
        config = configparser.ConfigParser()
        config.read('/opt/pphook/config.ini')
        return config
    else:
        logger.error("Impossible de créer la configuration depuis les secrets")
        return None

if __name__ == "__main__":
    # Test du loader
    logging.basicConfig(level=logging.INFO)
    config = load_config_from_docker_secrets()
    if config:
        print("Configuration chargée avec succès!")
        for section in config.sections():
            print(f"\n[{section}]")
            for key, value in config.items(section):
                print(f"{key} = {value}")
    else:
        print("Échec du chargement de la configuration")
