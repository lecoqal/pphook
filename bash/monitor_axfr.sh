#!/bin/bash

echo "$(date): Début script monitor_axfr"

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================
# Déchiffrer et charger les variables (exactement comme ton script qui fonctionne)
eval "$(gpg --batch --passphrase-file ../.gpg_passphrase --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# VÉRIFICATION AXFR
# ==========================================
echo "=== Vérification AXFR ==="

# Récupération automatique des zones depuis PowerDNS
zones=$(curl --noproxy "*" -s -H "X-API-Key: $PDNS_API_KEY" "$PDNS_API_URL/servers/localhost/zones" | jq -r '.[].name' | sed 's/\.$//')

for zone in $zones; do
    echo -n "Zone $zone: "
    
    # Récupération du serial master via API PowerDNS
    master_serial=$(curl --noproxy "*" -s -H "X-API-Key: $PDNS_API_KEY" "$PDNS_API_URL/servers/localhost/zones/$zone" | jq -r '.rrsets[] | select(.type=="SOA") | .records[0].content' | awk '{print $3}')
    
    # Récupération des serials slaves via DNS (méthode +short position 3)
    slave1_serial=$(timeout 5 dig @"$NS01_IP" "$zone" SOA +short 2>/dev/null | awk '{print $3}')
    slave2_serial=$(timeout 5 dig @"$NS02_IP" "$zone" SOA +short 2>/dev/null | awk '{print $3}')
    
    # Debug si vide
    if [[ -z "$master_serial" ]]; then
        echo "ERREUR - Pas de réponse du master"
        continue
    fi
    
    # Vérification
    if [[ "$master_serial" == "$slave1_serial" && "$master_serial" == "$slave2_serial" ]]; then
        echo "OK (serial: $master_serial)"
    else
        echo "ERREUR - Master: $master_serial, Slave1: $slave1_serial, Slave2: $slave2_serial"
    fi
done

echo "$(date): Fin script monitor_axfr"
