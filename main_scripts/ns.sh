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
    
    // Listen on all interfaces
    listen-on { any; };
    listen-on-v6 { any; };
    
    // Allow recursive queries
    allow-recursion { any; };
    recursion yes;
    
    // Zone transfers
    allow-transfer { none; };  // Disable transfers to other servers
    
    // Notifications
    allow-notify { $PDNS_IP; };
    
    // Miscellaneous
    notify no;                // Don't send notifications (slave only)
    minimal-responses yes;
    
    // Logging
    dnssec-validation auto;
    auth-nxdomain no;
};
EOF

# ==========================================
# CREATE USER BIND_USER
# ==========================================
# Create user
useradd -m -s /bin/bash $BIND_USER

# Defined password
echo "$BIND_USER:$BIND_USER_PASSWORD" | chpasswd

#Add to sudoers
export PATH=$PATH:/usr/sbin:/sbin
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
