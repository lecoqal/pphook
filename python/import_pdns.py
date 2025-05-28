#!/usr/bin/env python3

import json
import pymysql
import json
import sys
import os
import subprocess
import configparser
from pdns import PowerDNSAPI

command = 'source /opt/PowerDNS-Admin/pdns_venv/bin/activate'
subprocess.run(command, shell=True, capture_output=True, text=True, executable='/bin/bash')

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
INPUT_FILE = f"{vars['PROJECT_PATH']}/powerdns_export.json"

def main():
    # Charger les données
    with open(INPUT_FILE, 'r') as f:
        zones = json.load(f)
    
    # Connexion DB
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    cursor = conn.cursor()
    
    # Option 3 : Vider complètement la base avant import
    print("Suppression des données existantes...")
    cursor.execute("DELETE FROM records")
    cursor.execute("DELETE FROM domains")
    cursor.execute("DELETE FROM domainmetadata")  # Supprimer aussi les métadonnées
    conn.commit()
    print("Base vidée")
    
    print(f"Import de {len(zones)} zones...")
    
    for zone in zones:
        zone_name = zone['name']
        zone_type = zone['type']
        
        print(f"Zone: {zone_name}")
        
        # Créer le domaine
        cursor.execute(
            "INSERT INTO domains (name, type) VALUES (%s, %s)",
            (zone_name, zone_type)
        )
        domain_id = cursor.lastrowid
        
        # Créer les records
        for record in zone['records']:
            cursor.execute("""
                INSERT INTO records (domain_id, name, type, content, ttl) 
                VALUES (%s, %s, %s, %s, %s)
            """, (
                domain_id,
                record['name'],
                record['type'],
                record['content'],
                record['ttl']
            ))
        
        print(f"  {len(zone['records'])} records importés")
    
    # Sauvegarder
    conn.commit()
    cursor.close()
    conn.close()
    
    print("Import terminé!")

if __name__ == "__main__":
    main()
