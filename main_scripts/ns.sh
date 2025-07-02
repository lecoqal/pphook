#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# DEPENDENCIES
# ==========================================
apt-get update
apt-get install bind9 bind9utils openssh-server -y

# ==========================================
# RESOLV.CONF CONFIG
# ==========================================
cat <<EOF >/etc/resolv.conf
nameserver 127.0.0.1
nameserver 8.8.8.8
options timeout:1
options attempts:2
options rotate
options ndots:1
EOF

# ==========================================
# OPTIONS FILE CONFIG
# ==========================================
cat <<EOF >/etc/bind/named.conf.options
options {
    directory "/var/cache/bind";

    // Pour un slave, désactiver la récursion (sécurité)
    recursion no;

    // Autoriser les requêtes
    allow-query { any; };

    // Pas de récursion pour les slaves
    allow-recursion { none; };

    // Interdire les transferts
    allow-transfer { none; };

    // Accepter les notifications uniquement du maître
    allow-notify { $PDNS_IP; };  // IP PowerDNS master

    // Configuration DNSSEC
    dnssec-validation auto;

    // Restrictions
    auth-nxdomain no;
    listen-on-v6 { none; };

    // Écouter sur toutes les interfaces
    listen-on { any; };

    // Désactiver la version (sécurité)
    version none;
};
EOF

# ==========================================
# CREATE USER BIND_USER
# ==========================================
# Create user
export PATH=$PATH:/usr/sbin:/sbin
useradd -m -s /bin/bash $BIND_USER

# Defined password
echo "$BIND_USER:$BIND_USER_PASSWORD" | chpasswd

#Add to sudoers
usermod -aG sudo $BIND_USER

# Give perms on /etc/bind
chown -R $BIND_USER:$BIND_USER /etc/bind
chmod -R 775 /etc/bind

echo "User $BIND_USER created with perms on /etc/bind"

# ==========================================
# TSIG KEY
# ==========================================
#cat <<EOF >/etc/bind/transfer.key
#key "transfer.key" {
#    algorithm hmac-sha256;
#    secret "$TSIG_KEY";
#};
#EOF

# Secure permissions
#chmod 640 /etc/bind/transfer.key
#chown $BIND_USER:$BIND_USER /etc/bind/transfer.key

# ==========================================
# START BIND
# ==========================================
systemctl restart bind9
systemctl restart ssh
systemctl status bind9
