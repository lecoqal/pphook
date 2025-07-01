#!/bin/bash

echo "$(date): Début script push_dns_conf"

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --batch --passphrase-file ../.gpg_passphrase --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# EXECUTE PYTHON SCRIPT
# ==========================================
cd ../python/
python3 bind_local_gen.py
cd ../bash/

# Variables
SOURCE="../python/output/named.conf.local"
DESTINATION1="$BIND_USER@$NS01_IP_MGMT:/etc/bind/"
DESTINATION2="$BIND_USER@$NS02_IP_MGMT:/etc/bind/"

# Copie via SCP
sshpass -p "$BIND_USER_PASSWORD" scp "$SOURCE" "$DESTINATION1"
sshpass -p "$BIND_USER_PASSWORD" scp "$SOURCE" "$DESTINATION2"
