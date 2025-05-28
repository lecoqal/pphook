#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# PHPIPAM SQL INJECTION
# ==========================================
echo "PHPIPAM data injection in progress..."
source  $PROJECT_PATH/bash/ipam_sql_injection

# ==========================================
# POWERDNS SQL INJECTION
# ==========================================
echo "Powerdns data export in progress..."
python3 $PROJECT_PATH/python/export_pdns.py
echo "Powerdns data import in progress..."
python3 $PROJECT_PATH/python/import_pdns.py
