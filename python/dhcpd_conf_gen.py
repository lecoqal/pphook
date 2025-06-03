#!/usr/bin/env python3
import sys
import os
import subprocess
import requests
import time
import logging
import ipaddress
import json
import configparser
from phpipam import PhpIPAMAPI as ipam
from jinja2 import Environment, FileSystemLoader

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Activation de l'environnement virtuel
command = 'source /opt/pphook/pphook_venv/bin/activate'
subprocess.run(command, shell=True, capture_output=True, text=True, executable='/bin/bash')

# Templates Jinja2
env = Environment(loader=FileSystemLoader("templates/"))
template_resa = env.get_template("dhcpd_conf_resa.j2")
template_subnets = env.get_template("dhcpd_conf_subnets.j2")

# Fichiers de sortie
filename_resa = "output/dhcpd_resa.conf"
filename_subnets = "output/dhcpd_subnets.conf"

def load_bash_vars(env_file_path="../.env.gpg"):
    """Charge les variables depuis un fichier .env chiffré"""
    command = f'gpg --quiet --decrypt {env_file_path} 2>/dev/null | grep -E "^[A-Z_]+=" '
    result = subprocess.run(command, shell=True, capture_output=True, text=True, executable='/bin/bash')
    
    if result.returncode != 0:
        raise Exception(f"Erreur lors du déchiffrement de {env_file_path}")
    
    vars_dict = {}
    for line in result.stdout.split('\n'):
        if '=' in line and not line.startswith('_'):
            key, value = line.split('=', 1)
            value = value.strip().strip('"').strip("'")
            vars_dict[key] = value
    
    return vars_dict

def calculate_network_info(subnet_cidr):
    """Calcule les informations réseau à partir d'un CIDR"""
    try:
        network = ipaddress.IPv4Network(subnet_cidr, strict=False)
        return {
            'network': str(network.network_address),
            'netmask': str(network.netmask),
            'gateway': str(network.network_address + 254),  # .254 comme gateway
            'range_start': str(network.network_address + 200),  # .200
            'range_end': str(network.network_address + 209)     # .209
        }
    except Exception as e:
        logger.error(f"Erreur calcul réseau pour {subnet_cidr}: {e}")
        return None

def process_subnet_reservations(subnets, reserved_subnet_ids, class_list):
    """Traite les subnets pour les réservations DHCP"""
    processed_subnets = []
    
    for subnet in subnets:
        subnet_id = str(subnet.get('id'))
        
        # Vérifier si ce subnet est dans la liste des réservations
        if subnet_id in reserved_subnet_ids:
            # Construire le CIDR
            subnet_addr = subnet.get('subnet', '')
            mask = subnet.get('mask', '')
            
            if subnet_addr and mask:
                subnet_cidr = f"{subnet_addr}/{mask}"
                network_info = calculate_network_info(subnet_cidr)
                
                if network_info:
                    # Trouver les classes associées à ce subnet
                    associated_classes = [
                        cls for cls in class_list 
                        if str(cls.get('subnet_id')) == subnet_id
                    ]
                    
                    subnet_data = {
                        'id': subnet_id,
                        'description': subnet.get('description', f'Subnet {subnet_addr}'),
                        'subnet': network_info['network'],
                        'netmask': network_info['netmask'],
                        'gateway': network_info['gateway'],
                        'range_start': network_info['range_start'],
                        'range_end': network_info['range_end'],
                        'associated_classes': associated_classes
                    }
                    
                    processed_subnets.append(subnet_data)
                    logger.info(f"Subnet traité: {subnet_addr}/{mask} (ID: {subnet_id})")
    
    return processed_subnets

def generate_dhcp_classes(class_list, class_mac_dict):
    """Génère les définitions de classes DHCP"""
    dhcp_classes = []
    
    for class_info in class_list:
        class_name = class_info.get('class_name')
        
        # Récupérer les MACs pour cette classe
        mac_key = f"class_{class_name}_mac"
        mac_addresses = class_mac_dict.get(mac_key, [])
        
        if mac_addresses:
            # Construire la condition de match
            match_conditions = []
            for mac in mac_addresses:
                # Normaliser la MAC (format XX:XX:XX)
                if len(mac) >= 6:
                    formatted_mac = f"{mac[0:2]}:{mac[2:4]}:{mac[4:6]}"
                    match_conditions.append(f'substring(hardware, 1, 3) = {formatted_mac}')
            
            if match_conditions:
                dhcp_class = {
                    'name': class_name,
                    'match_condition': ' or\n                '.join(match_conditions)
                }
                dhcp_classes.append(dhcp_class)
                logger.info(f"Classe DHCP créée: {class_name} avec {len(mac_addresses)} MACs")
    
    return dhcp_classes

# Chargement des variables
try:
    vars = load_bash_vars('../.env.gpg')
except Exception as e:
    logger.error(f"Erreur chargement variables: {e}")
    sys.exit(1)

# Variables phpIPAM
IPAM_IP = vars["IPAM_IP"]
IPAM_API_URL = vars["IPAM_API_URL"]
IPAM_APP_ID = vars["IPAM_APP_ID"]
IPAM_USERNAME = vars["IPAM_USERNAME"]
IPAM_PASSWORD = vars["IPAM_PASSWORD"]
SUBNETS_LIST = vars["SUBNETS_LIST"].split(',') if vars.get("SUBNETS_LIST") else []

# Configuration des classes DHCP (à adapter selon tes besoins)
class_list = [
    {"class_name": "infra_servers", "subnet_id": "12"},
    {"class_name": "infra_workstations", "subnet_id": "15"},
    {"class_name": "lise_devices", "subnet_id": "18"},
    # Ajouter d'autres classes selon tes besoins
]

# MACs par classe (à remplir avec tes données)
class_mac_dict = {
    "class_infra_servers_mac": ["001122", "334455", "667788"],
    "class_infra_workstations_mac": ["aabbcc", "ddeeff", "112233"],
    "class_lise_devices_mac": ["445566", "778899", "aabbdd"],
    # Ajouter d'autres MACs selon tes classes
}

# Proxy bypass
os.environ['no_proxy'] = f'{IPAM_IP},localhost,127.0.0.1'
os.environ['NO_PROXY'] = f'{IPAM_IP},localhost,127.0.0.1'

# Connexion phpIPAM
try:
    phpipam = ipam(IPAM_API_URL, IPAM_APP_ID, IPAM_USERNAME, IPAM_PASSWORD)
    if not phpipam.authenticate():
        raise Exception("Échec de l'authentification phpIPAM")
    logger.info("Connexion phpIPAM réussie")
except Exception as e:
    logger.error(f"Erreur connexion phpIPAM: {e}")
    sys.exit(1)

########################
### PARTIE RESA HOST ###
########################

# Récupération des IPs pour les réservations d'hôtes
ip_list = phpipam.get_addresses_with_mac_and_dhcp_profil()

# Filtrage par profil pour les réservations
reservations_infra = []
reservations_lise = []

for ip in ip_list:
    if ip["dhcp_profil"] == "infra":
        reservations_infra.append(ip)
    elif ip["dhcp_profil"] == "lise":
        reservations_lise.append(ip)

# Génération du fichier de réservations d'hôtes
try:
    content_resa = template_resa.render(
        reservations_infra=reservations_infra,
        reservations_lise=reservations_lise
    )
    
    os.makedirs("output", exist_ok=True)
    with open(filename_resa, mode="w", encoding="utf-8") as output:
        output.write(content_resa)
    
    logger.info(f"Fichier généré: {filename_resa}")
    print(f"✓ Réservations d'hôtes générées: {len(reservations_infra)} infra, {len(reservations_lise)} lise")
    
except Exception as e:
    logger.error(f"Erreur génération réservations: {e}")

######################
### PARTIE SUBNETS ###
######################

try:
    # Récupération de tous les subnets
    all_subnets = phpipam.get_subnets()
    logger.info(f"Récupéré {len(all_subnets)} subnets depuis phpIPAM")
    
    # Traitement des subnets pour réservation
    processed_subnets = process_subnet_reservations(all_subnets, SUBNETS_LIST, class_list)
    
    # Génération des classes DHCP
    dhcp_classes = generate_dhcp_classes(class_list, class_mac_dict)
    
    # Génération du fichier de configuration des subnets
    content_subnets = template_subnets.render(
        dhcp_classes=dhcp_classes,
        subnets=processed_subnets
    )
    
    with open(filename_subnets, mode="w", encoding="utf-8") as output:
        output.write(content_subnets)
    
    logger.info(f"Fichier généré: {filename_subnets}")
    print(f"✓ Configuration subnets générée: {len(processed_subnets)} subnets, {len(dhcp_classes)} classes")
    
except Exception as e:
    logger.error(f"Erreur génération subnets: {e}")
    sys.exit(1)

print("\n🎉 Génération terminée avec succès!")
print(f"📁 Fichiers générés:")
print(f"   - {filename_resa}")
print(f"   - {filename_subnets}")
