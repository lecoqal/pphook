#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

echo "Veuillez spécifier l'emplacement du fichier dump SQL"
read DUMP_PATH

mysql -u $IPAM_DB_USER -p$IPAM_DB_PASS -h $DB_IP $IPAM_DB_NAME < $DUMP_PATH

