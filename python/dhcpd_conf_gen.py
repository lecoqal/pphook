#!/usr/bin/env python3

import sys
import os
import subprocess
import requests
import time
import logging

command = 'source /opt/pphook/pphook_venv/bin/activate'
subprocess.run(command, shell=True, capture_output=True, text=True, executable='/bin/bash')

import json
import configparser
from phpipam import PhpIPAMAPI as ipam
from jinja2 import Environment, FileSystemLoader

# Templates
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

# Chargement des variables
vars = load_bash_vars('../.env.gpg')

# Variables phpIPAM
IPAM_IP = vars["IPAM_IP"]
IPAM_API_URL = vars["IPAM_API_URL"]
IPAM_APP_ID = vars["IPAM_APP_ID"]
IPAM_USERNAME = vars["IPAM_USERNAME"]
IPAM_PASSWORD = vars["IPAM_PASSWORD"]

# Proxy bypass
os.environ['no_proxy'] = f'{IPAM_IP},localhost,127.0.0.1'
os.environ['NO_PROXY'] = f'{IPAM_IP},localhost,127.0.0.1'

# Connexion phpIPAM
phpipam = ipam(IPAM_API_URL, IPAM_APP_ID, IPAM_USERNAME, IPAM_PASSWORD)
phpipam.authenticate()

# Récupération des IPs
ip_list = phpipam.get_addresses_with_mac_and_dhcp_profil()

# Filtrage par profil pour les réservations
reservations_infra = []
reservations_lise = []

for ip in ip_list:
    if ip["dhcp_profil"] == "infra":
        reservations_infra.append(ip)
    elif ip["dhcp_profil"] == "lise":
        reservations_lise.append(ip)

# Génération du fichier de réservations
content_resa = template_resa.render(
    reservations_infra=reservations_infra,
    reservations_lise=reservations_lise
)

with open(filename_resa, mode="w", encoding="utf-8") as output:
    output.write(content_resa)
    print("wrote", filename_resa)
