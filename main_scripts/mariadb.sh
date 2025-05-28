#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# DEPENDENCIES
# ==========================================
apt update && apt install -y mariadb-server

# ==========================================
# SECURE INSTALL
# ==========================================
mysql_secure_installation

# ==========================================
# ACCEPT REMOTE CONNECTIONS
# ==========================================
sed -i 's/bind-address\s*=\s*127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf

# ==========================================
# CREATE DATABASES AND USERS
# ==========================================
mysql -u root -p <<EOF
CREATE DATABASE phpipam;
CREATE DATABASE powerdns;
CREATE DATABASE pdnsadmin;

CREATE USER '$IPAM_DB_USER'@'$IPAM_IP' IDENTIFIED BY '$IPAM_DB_PASS';
GRANT ALL PRIVILEGES ON $IPAM_DB_NAME.* TO '$IPAM_DB_USER'@'$IPAM_IP';
GRANT ALL PRIVILEGES ON $PDNS_DB_NAME.* TO '$IPAM_DB_USER'@'$IPAM_IP';

CREATE USER '$PDNS_DB_USER'@'$PDNS_IP' IDENTIFIED BY '$PDNS_DB_PASS';
GRANT ALL PRIVILEGES ON $PDNS_DB_NAME.* TO '$PDNS_DB_USER'@'$PDNS_IP';

CREATE USER '$PDNSADMIN_DB_USER'@'$PDNS_IP' IDENTIFIED BY '$PDNSADMIN_DB_PASS';
GRANT ALL PRIVILEGES ON $PDNSADMIN_DB_NAME.* TO '$PDNSADMIN_DB_USER'@'$PDNS_IP';

FLUSH PRIVILEGES;
EOF

# ==========================================
# START SERVICE
# ==========================================
systemctl restart mariadb
