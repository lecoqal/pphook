#!/bin/bash

echo "$(date): Début script push_dhcp_conf"

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --batch --passphrase-file ../.gpg_passphrase --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# EXECUTE PYTHON SCRIPT
# ==========================================
cd ../python/
python3 dhcpd_conf_gen.py
cd ../bash/

# Variables
SOURCE="../python/output/dhcpd_resa.conf"
DESTINATION="$DHCP_USER@$DHCP_IP:/etc/dhcp/"

sshpass -p "$DHCP_USER_PASSWORD" scp "$SOURCE" "$DESTINATION"

echo "Envoi du fichier de configuration DHCP terminé!"
