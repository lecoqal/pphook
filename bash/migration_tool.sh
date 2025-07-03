#!/bin/bash

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
# CHOIX DU MODE DE CONFIGURATION
# ==========================================

echo ""
echo "=== Configuration des variables ==="
echo "1) Variables automatiques (déchiffrement .env.gpg)"
echo "2) Variables manuelles"
read -p "Choix: " config_mode

if [ "$config_mode" = "1" ]; then
    echo "Déchiffrement des variables..."
    eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"
    echo "✓ Variables chargées depuis .env.gpg"
    
    # Choix local/distant seulement en mode automatique
    echo ""
    echo "=== Choix de la base ==="
    echo "1) Base locale (utilise DB_IP=$DB_IP)"
    echo "2) Base distante"
    read -p "Choix: " db_location
    
    if [ "$db_location" = "2" ]; then
        read -p "Adresse IP distante: " DB_IP
    fi
else
    echo ""
    echo "=== Saisie manuelle des variables ==="
    
    read -p "Adresse IP base de données: " DB_IP
    
    echo ""
    echo "phpIPAM:"
    read -p "Nom de la base: " IPAM_DB_NAME
    read -p "Utilisateur: " IPAM_DB_USER
    read -s -p "Mot de passe: " IPAM_DB_PASS
    echo ""
    
    echo ""
    echo "PowerDNS:"
    read -p "Nom de la base: " PDNS_DB_NAME
    read -p "Utilisateur: " PDNS_DB_USER
    read -s -p "Mot de passe: " PDNS_DB_PASS
    echo ""
    
    # Variables Hook seulement si Import
    if [ "$action" = "2" ]; then
        echo ""
        echo "Hook (pour reset timestamp):"
        read -p "IP serveur Hook: " HOOK_IP
        read -p "Utilisateur SSH Hook: " HOOK_USER
    fi
    
    echo "✓ Variables configurées manuellement"
fi

echo ""
echo "INFO: Utilisation de DB_IP=$DB_IP"

# ==========================================
# CONFIGURATION TABLES
# ==========================================

# Tables phpIPAM essentielles pour migration
PHPIPAM_TABLES="sections subnets ipaddresses vlans vlanDomains devices deviceTypes users userGroups customers locations"

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
        echo "✗ Connexion échouée vers $DB_IP"
        return 1
    fi
    echo "✓ Connexion OK"
    
    for table in $tables; do
        echo "Export: $table"
        echo "DEBUG: mysqldump -u $db_user -p*** -h $DB_IP --single-transaction $db_name $table"
        
        if mysqldump -u "$db_user" -p"$db_pass" -h "$DB_IP" \
            --single-transaction \
            --complete-insert \
            "$db_name" "$table" > "$output_dir/${table}.sql"; then
            echo "✓ $table ($(wc -l < "$output_dir/${table}.sql") lignes)"
        else
            echo "✗ $table - Erreur export"
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
        echo "✗ Connexion échouée vers $DB_IP"
        return 1
    fi
    echo "✓ Connexion OK"
    
    for sql_file in "$input_dir"/*.sql; do
        [ ! -f "$sql_file" ] && continue
        
        table=$(basename "$sql_file" .sql)
        echo "Import: $table"
        echo "DEBUG: mysql -u $db_user -p*** -h $DB_IP $db_name < $sql_file"
        
        if mysql -u "$db_user" -p"$db_pass" -h "$DB_IP" "$db_name" < "$sql_file" 2>/dev/null; then
            echo "✓ $table"
        else
            echo "✗ $table - Erreur import"
        fi
    done
}

# ==========================================
# MENU PRINCIPAL
# ==========================================

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
