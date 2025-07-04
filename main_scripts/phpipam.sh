#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# DEPENDENCIES
# ==========================================
apt update && apt install -y \
    apache2 \
    php \
    php-cli \
    php-mysql \
    php-gmp \
    php-curl \
    php-bcmath \
    php-gd \
    php-mbstring \
    php-ldap \
    php-xml \
    php-intl \
    git \
    unzip

# ==========================================
# CONFIG APACHE2
# ==========================================
cat > /etc/apache2/sites-available/phpipam.conf << EOF
<VirtualHost *:80>
    ServerName $IPAM_IP
    DocumentRoot /var/www/html/phpipam
    
    <Directory /var/www/html/phpipam>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/phpipam-error.log
    CustomLog \${APACHE_LOG_DIR}/phpipam-access.log combined
</VirtualHost>
EOF

# Activate Site
a2dissite /etc/apache2/sites-enabled/000-default.conf
a2ensite phpipam.conf
a2enmod rewrite

# ==========================================
# PHPIPAM INSTALL
# ==========================================
# Cleanup if a previous installation exists
if [ -d "/var/www/html/phpipam" ]; then
    echo "Suppression de l'installation précédente..."
    rm -rf /var/www/html/phpipam
fi    

# PHPIPAM Cloning
cd /var/www/html/
git clone https://github.com/phpipam/phpipam.git
cd phpipam/
git checkout $PHPIPAM_VERSION

# ==========================================
# PHPIPAM CONFIG
# ==========================================
cp config.dist.php config.php
cd /var/www/html/phpipam

# DB Configuration
sed -i "s/\$db\['host'\] = '.*';/\$db\['host'\] = '$DB_IP';/" config.php
sed -i "s/\$db\['user'\] = '.*';/\$db\['user'\] = '$IPAM_DB_USER';/" config.php
sed -i "s/\$db\['pass'\] = '.*';/\$db\['pass'\] = '$IPAM_DB_PASS';/" config.php
sed -i "s/\$db\['name'\] = '.*';/\$db\['name'\] = '$IPAM_DB_NAME';/" config.php
sed -i "s/\$db\['port'\] = .*;/\$db\['port'\] = $DB_PORT;/" config.php

# Optional Config
# Enable API
sed -i '/<?php/a \
$api_allow = true;' config.php
sed -i 's/\$api_allow_unsafe *= *.\+;/$api_allow_unsafe = true;/g' config.php

# ==========================================
# SET PERMISSIONS
# ==========================================
chown -R www-data:www-data /var/www/html/phpipam
chmod -R 755 /var/www/html/phpipam

# ==========================================
# DB CONNECTION TEST
# ==========================================
echo "Testing the database connection..."
    
# Create a temporary PHP script to test the connection
cat > /tmp/test_db_connection.php << EOF
<?php
\$db_host = '$DB_IP';
\$db_user = '$IPAM_DB_USER';
\$db_pass = '$IPAM_DB_PASS';
\$db_name = '$IPAM_DB_NAME';
\$db_port = (int)'$IPAM_DB_PORT';

try {
    \$conn = new mysqli(\$db_host, \$db_user, \$db_pass, \$db_name, \$db_port);
    if (\$conn->connect_error) {
        throw new Exception("Connection failed: " . \$conn->connect_error);
    }
    echo "[SUCCESS] - Database connection successful";
    \$conn->close();
} catch (Exception \$e) {
    echo "[ERROR] - CONNECTION ERROR: " . \$e->getMessage();
    exit(1);
}
EOF
    
php /tmp/test_db_connection.php
rm /tmp/test_db_connection.php

# ==========================================
# START APACHE2 SERVICE
# ==========================================
systemctl restart apache2

# ==========================================
# DISPLAY FINAL INFO
# ==========================================
echo -e "\n=== INSTALLATION COMPLETE ==="
echo "phpIPAM is now installed and configured."
echo ""
echo "Access URL: http://$IPAM_IP"
echo ""
echo "=== INITIAL SETUP ==="
echo "1. Restart Apache: systemctl restart apache2"
echo "2. Access http://$IPAM_IP to complete the installation"
echo "3. On first access:"
echo "   - Click on 'New phpipam installation'"
echo "   - Then click on 'automatic database installation'"
echo "   - Enter the database information as shown below"
echo "   - Follow phpipam installation wizard"
echo ""
echo "Database configuration:"
echo "  Host: $DB_IP"
echo "  Port: $DB_PORT"
echo "  Database: $IPAM_DB_NAME"
echo "  User: $IPAM_DB_USER"
echo "  Password: $IPAM_DB_PASS"
echo ""
echo "=== POST-INSTALLATION COMMANDS ==="
echo "After successful installation, execute this command:"
echo "  sed -i 's/^\$disable_installer *= *false;/$disable_installer = true;/' /var/www/html/phpipam/config.php"
echo ""
echo "=== phpIPAM SETTINGS CONFIGURATION ==="
echo "Go to Administration → phpIPAM Settings:"
echo "  Enable API: Turn ON"
echo "  Enable PowerDNS: Turn ON"
echo "  Resolve DNS Names: Turn ON"
echo "  Allow Duplicate VLANs: Turn OFF"
echo "  Hide Donation Button: Turn ON"
echo ""
echo "=== API CONFIGURATION ==="
echo "Go to Administration → API Management:"
echo "  1. Create new API application"
echo "  2. Set Application ID (example: 'pphook')"
echo "  3. Choose 'User token' authentication"
echo "  4. Note the APP_ID for configuration"
echo ""
echo "Then update your global_vars.sh with:"
echo "  IPAM_APP_ID=\"your-app-id\""
echo "  IPAM_API_KEY=\"your-api-key\""
echo "  IPAM_USERNAME=\"ipam-username\""
echo "  IPAM_PASSWORD=\"ipam-password\""
echo ""
echo "=== PowerDNS INTEGRATION ==="
echo "Go to Administration → PowerDNS:"
echo "  1. Enter PowerDNS database settings:"
echo "     - Host: $DB_IP"
echo "     - Database: $PDNS_DB_NAME"
echo "     - Username: $IPAM_DB_USER"
echo "     - Password: $IPAM_DB_PASS"
echo "  2. Auto-Serial: Turn OFF"
echo "  3. Create Default Zone Configuration"
echo ""
echo "=== CUSTOM FIELDS (Optional) ==="
echo "Go to Administration → Custom Fields:"
echo "  - Add 'DHCP_Profil' field for IP addresses"
echo "  - Type: enum"
echo "  - Values: infra,lise"
echo ""
echo "=== VERIFICATION ==="
echo "Test your setup:"
echo "  1. Create a test IP address with hostname"
echo "  2. Verify API access: curl http://$IPAM_IP/api/pphook/sections/"
echo "  3. Check PowerDNS integration in phpIPAM"
