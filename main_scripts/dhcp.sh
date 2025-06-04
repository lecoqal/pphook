#/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# DEPENDENCIES
# ==========================================
apt-get update
apt-get install isc-dhcp-server openssh-server -y

# ==========================================
# CREATE USER $DHCP_USER
# ==========================================
# Create user
useradd -m -s /bin/bash $DHCP_USER

# Defined password
echo "$DHCP_USER:$DHCP_USER_PASSWORD" | chpasswd

#Add to sudoers
export PATH=$PATH:/usr/sbin:/sbin
usermod -aG sudo $DHCP_USER

# Give perms on /etc/bind
chown -R $DHCP_USER:$DHCP_USER /etc/bind
chmod -R 775 /etc/bind

echo "User $DHCP_USER created with perms on /etc/bind"

# ==========================================
# START SERVICE
# ==========================================

systemctl restart isc-dhcp-server
systemctl restart ssh
systemctl status isc-dhcp-server
