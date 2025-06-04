#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# DEPENDENCIES
# ==========================================

apt install curl jq -y

# Variables
SLAVE1="$NS01_IP"
SLAVE2="$NS02_IP"

echo "=== Vérification AXFR ==="

# Récupération automatique des zones depuis PowerDNS
zones=$(curl -s -H "X-API-Key: $PDNS_API_KEY" $PDNS_API_URL/servers/localhost/zones | jq -r '.[].name' | sed 's/\.$//')

for zone in $zones; do
    echo -n "Zone $zone: "
    
    # Récupération des serials
    master_serial=$(dig @127.0.0.1 $zone SOA +short | awk '{print $3}')
    slave1_serial=$(dig @$SLAVE1 $zone SOA +short | awk '{print $3}')
    slave2_serial=$(dig @$SLAVE2 $zone SOA +short | awk '{print $3}')
    
    # Vérification
    if [[ "$master_serial" == "$slave1_serial" && "$master_serial" == "$slave2_serial" ]]; then
        echo "OK (serial: $master_serial)"
    else
        echo "ERREUR - Master: $master_serial, Slave1: $slave1_serial, Slave2: $slave2_serial"
    fi
done
