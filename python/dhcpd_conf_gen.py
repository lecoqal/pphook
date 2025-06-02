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

env = Environment(loader=FileSystemLoader("templates/"))
template = env.get_template("dhcpd_conf.j2")
filename = "output/dhcpd.conf"


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

# Utilisation
vars = load_bash_vars('../.env.gpg')

# Accéder aux variables
DB_HOST = vars["DB_IP"]
DB_USER = vars["PDNS_DB_USER"]
DB_PASSWORD = vars["PDNS_DB_PASS"]
DB_NAME = vars["PDNS_DB_NAME"]
IPAM_IP = vars["IPAM_IP"]
IPAM_API_URL = vars["IPAM_API_URL"]
IPAM_APP_ID = vars["IPAM_APP_ID"]
IPAM_USERNAME = vars["IPAM_USERNAME"]
IPAM_PASSWORD = vars["IPAM_PASSWORD"]

# Proxy Restriction Bypass
os.environ['no_proxy'] = f'{IPAM_IP},localhost,127.0.0.1'
os.environ['NO_PROXY'] = f'{IPAM_IP},localhost,127.0.0.1'

phpipam = ipam(IPAM_API_URL, IPAM_APP_ID, IPAM_USERNAME, IPAM_PASSWORD)
phpipam.authenticate()
ipaddrs = phpipam.get_addresses()
print(ipaddrs) 
