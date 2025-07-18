#!/bin/bash

# ==========================================
# COULEURS
# ==========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ==========================================
# MENU PRINCIPAL
# ==========================================

echo "=== Outil de migration phpIPAM/PowerDNS ==="
echo "1) Export"
echo "2) Import"
read -p "Choix: " action

echo ""
echo "Système:"
echo "1) phpIPAM"
echo "2) PowerDNS"
echo "3) Les deux"
read -p "Choix: " system

# ==========================================
# SAISIE DES VARIABLES
# ==========================================

echo ""
echo "=== Saisie des variables ==="

read -p "Adresse IP base de données: " DB_IP

# Demander les infos phpIPAM seulement si nécessaire
if [ "$system" = "1" ] || [ "$system" = "3" ]; then
    echo ""
    echo "phpIPAM:"
    read -p "Nom de la base: " IPAM_DB_NAME
    read -p "Utilisateur: " IPAM_DB_USER
    read -s -p "Mot de passe: " IPAM_DB_PASS
    echo ""
fi

# Demander les infos PowerDNS seulement si nécessaire
if [ "$system" = "2" ] || [ "$system" = "3" ]; then
    echo ""
    echo "PowerDNS:"
    read -p "Nom de la base: " PDNS_DB_NAME
    read -p "Utilisateur: " PDNS_DB_USER
    read -s -p "Mot de passe: " PDNS_DB_PASS
    echo ""
fi

# Variables Hook seulement si Import
if [ "$action" = "2" ]; then
    echo ""
    echo "Hook (pour reset timestamp):"
    read -p "IP serveur Hook: " HOOK_IP
    read -p "Utilisateur SSH Hook: " HOOK_USER
fi

echo -e "${GREEN}[SUCCESS]${NC} Variables configurées"

echo ""
echo "INFO: Utilisation de DB_IP=$DB_IP"

# ==========================================
# CONFIGURATION TABLES
# ==========================================

# Tables phpIPAM essentielles pour migration
PHPIPAM_TABLES="sections subnets ipaddresses vlans vlanDomains devices deviceTypes users userGroups customers locations changelog"

# Tables PowerDNS essentielles
POWERDNS_TABLES="domains records domainmetadata cryptokeys"

# ==========================================
# FONCTIONS
# ==========================================

export_tables() {
    local db_name="$1"
    local db_user="$2"
    local db_pass="$3"
    local tables="$4"
    local output_dir="$5"

    mkdir -p "$output_dir"

    echo "DEBUG: Connexion vers $DB_IP avec user $db_user pour base $db_name"

    # Test de connexion d'abord
    echo "Test connexion..."
    if ! mysql -u "$db_user" -p"$db_pass" -h "$DB_IP" --connect-timeout=10 -e "SELECT 1;" "$db_name" ; then
        echo -e "${RED}[ERROR]${NC} Connexion échouée vers $DB_IP"
        return 1
    fi
    echo -e "${GREEN}[SUCCESS]${NC} Connexion OK"

    for table in $tables; do
        echo "Export: $table"
        echo "DEBUG: mysqldump -u $db_user -p*** -h $DB_IP --single-transaction $db_name $table"

        if mysqldump -u "$db_user" -p"$db_pass" -h "$DB_IP" \
            --single-transaction \
            --complete-insert \
            "$db_name" "$table" > "$output_dir/${table}.sql"; then
            echo -e "${GREEN}[SUCCESS]${NC} $table ($(wc -l < "$output_dir/${table}.sql") lignes)"
        else
            echo -e "${RED}[ERROR]${NC} $table - Erreur export"
        fi
    done
}

import_tables() {
    local db_name="$1"
    local db_user="$2"
    local db_pass="$3"
    local input_dir="$4"

    echo "DEBUG: Import vers $DB_IP avec user $db_user pour base $db_name"

    # Test de connexion d'abord
    echo "Test connexion..."
    if ! mysql -u "$db_user" -p"$db_pass" -h "$DB_IP" --connect-timeout=10 -e "SELECT 1;" "$db_name" >/dev/null 2>&1; then
        echo -e "${RED}[ERROR]${NC} Connexion échouée vers $DB_IP"
        return 1
    fi
    echo -e "${GREEN}[SUCCESS]${NC} Connexion OK"

    for sql_file in "$input_dir"/*.sql; do
        [ ! -f "$sql_file" ] && continue

        table=$(basename "$sql_file" .sql)
        echo "Import: $table"
        echo "DEBUG: mysql -u $db_user -p*** -h $DB_IP $db_name < $sql_file"

        if mysql -u "$db_user" -p"$db_pass" -h "$DB_IP" "$db_name" < "$sql_file" 2>/dev/null; then
            echo -e "${GREEN}[SUCCESS]${NC} $table"
        else
            echo -e "${RED}[ERROR]${NC} $table - Erreur import"
        fi
    done
}

# ==========================================
# RÉPERTOIRE DE TRAVAIL
# ==========================================

# Répertoire de travail
if [ "$action" = "1" ]; then
    read -p "Nom du répertoire d'export: " workdir
    mkdir -p "$workdir"
    echo "Export vers: $workdir"
else
    read -p "Répertoire des fichiers SQL: " workdir
    [ ! -d "$workdir" ] && { echo "Répertoire inexistant"; exit 1; }
fi

# ==========================================
# TRAITEMENT
# ==========================================

case "$action-$system" in
    "1-1") # Export phpIPAM
        echo "Export phpIPAM vers $workdir/phpipam/"
        export_tables "$IPAM_DB_NAME" "$IPAM_DB_USER" "$IPAM_DB_PASS" "$PHPIPAM_TABLES" "$workdir/phpipam"
        ;;
    "1-2") # Export PowerDNS
        echo "Export PowerDNS vers $workdir/powerdns/"
        export_tables "$PDNS_DB_NAME" "$PDNS_DB_USER" "$PDNS_DB_PASS" "$POWERDNS_TABLES" "$workdir/powerdns"
        ;;
    "1-3") # Export les deux
        echo "Export phpIPAM vers $workdir/phpipam/"
        export_tables "$IPAM_DB_NAME" "$IPAM_DB_USER" "$IPAM_DB_PASS" "$PHPIPAM_TABLES" "$workdir/phpipam"
        echo "Export PowerDNS vers $workdir/powerdns/"
        export_tables "$PDNS_DB_NAME" "$PDNS_DB_USER" "$PDNS_DB_PASS" "$POWERDNS_TABLES" "$workdir/powerdns"
        ;;
    "2-1") # Import phpIPAM
        echo "Import phpIPAM depuis $workdir/phpipam/"
        [ -d "$workdir/phpipam" ] && import_tables "$IPAM_DB_NAME" "$IPAM_DB_USER" "$IPAM_DB_PASS" "$workdir/phpipam" || echo "Dossier phpipam/ inexistant"
        ;;
    "2-2") # Import PowerDNS
        echo "Import PowerDNS depuis $workdir/powerdns/"
        [ -d "$workdir/powerdns" ] && import_tables "$PDNS_DB_NAME" "$PDNS_DB_USER" "$PDNS_DB_PASS" "$workdir/powerdns" || echo "Dossier powerdns/ inexistant"
        ;;
    "2-3") # Import les deux
        echo "Import phpIPAM depuis $workdir/phpipam/"
        [ -d "$workdir/phpipam" ] && import_tables "$IPAM_DB_NAME" "$IPAM_DB_USER" "$IPAM_DB_PASS" "$workdir/phpipam"
        echo "Import PowerDNS depuis $workdir/powerdns/"
        [ -d "$workdir/powerdns" ] && import_tables "$PDNS_DB_NAME" "$PDNS_DB_USER" "$PDNS_DB_PASS" "$workdir/powerdns"
        ;;
    *)
        echo "Choix invalide"
        exit 1
        ;;
esac

echo "=== Terminé ==="
[ "$action" = "1" ] && echo "Fichiers dans: $workdir"

# Reset du timestamp SEULEMENT si on fait un import
if [ "$action" = "2" ]; then
    echo "Reset du timestamp pphook pour vérification complète..."
    ssh $HOOK_USER@$HOOK_IP "python3 -c \"
import sys
sys.path.insert(0, '/opt/pphook')
from hook import reset_last_check
reset_last_check()
print('Timestamp reset')
\""
fi
