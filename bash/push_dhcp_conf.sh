#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# Variables
SOURCE="../python/output/dhcpd_resa.conf"
DESTINATION="$DHCP_USER@$DHCP_IP:/etc/dhcp/"

sshpass -p "$DHCP_USER_PASSWORD" scp "$SOURCE" "$DESTINATION"
