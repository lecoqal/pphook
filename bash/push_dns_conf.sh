#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# Variables
SOURCE="../python/output/named.conf.local"
DESTINATION1="$BIND_USER@$NS01_IP_MGMT:/etc/bind/"
DESTINATION2="$BIND_USER@$NS02_IP_MGMT:/etc/bind/"

# Copie via SCP
sshpass -p "$BIND_USER_PASSWORD" scp "$SOURCE" "$DESTINATION1"
sshpass -p "$BIND_USER_PASSWORD" scp "$SOURCE" "$DESTINATION2"
