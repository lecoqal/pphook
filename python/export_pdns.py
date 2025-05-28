#!/usr/bin/env python3

import json
import sys
import os
import subprocess
import configparser
from pdns import PowerDNSAPI

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
PDNS_API_URL = vars["PDNS_API_URL"]
PDNS_API_KEY = vars["PDNS_API_KEY"]
PDNS_IP = "localhost"
OUTPUT_FILE = "../powerdns_export.json"

def main():
    # Connexion à PowerDNS
    api = PowerDNSAPI(PDNS_API_URL, PDNS_API_KEY, PDNS_IP)

    # Récupérer toutes les zones
    zones = api.get_zones()
    if not zones:
        print("Aucune zone trouvée")
        return

    export_data = []

    # Pour each zone
    for zone in zones:
        zone_name_with_dot = zone.get('name', '')  # Garder le point
        zone_name_clean = zone_name_with_dot.rstrip('.')  # Pour l'affichage

        print(f"Export zone: {zone_name_clean}")

        # Utiliser le nom avec point pour l'API
        zone_details = api.get_zone(zone_name_with_dot)
        if not zone_details:
            continue

        zone_data = {
            'name': zone_name_clean,  # Sans point pour le JSON
            'type': zone_details.get('kind', 'Native'),
            'records': []
        }

        # Récupérer les records
        for rrset in zone_details.get('rrsets', []):
            for record in rrset.get('records', []):
                if record.get('disabled'):
                    continue

                zone_data['records'].append({
                    'name': rrset.get('name', '').rstrip('.'),  # Enlever le point final
                    'type': rrset.get('type', ''),
                    'content': record.get('content', ''),
                    'ttl': rrset.get('ttl', 3600)
                })

        export_data.append(zone_data)

    # Sauvegarder
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(export_data, f, indent=2)

    print(f"Export terminé: {len(export_data)} zones dans {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
