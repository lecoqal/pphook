#!/bin/bash

# ==========================================
# IMPORT GLOBAL VARS
# ==========================================

# Déchiffrer et charger les variables
eval "$(gpg --quiet --decrypt ../.env.gpg 2>/dev/null | grep -E '^[A-Z_]+=.*' | sed 's/^/export /')"

# ==========================================
# DEPENDENCIES
# ==========================================
apt update && apt upgrade -y
apt-get install pdns-server pdns-backend-mysql -y

# ==========================================
# DATABASE CONFIG
# ==========================================
mysql -u "$PDNS_DB_USER" -h "$DB_IP" -p"$PDNS_DB_PASS" "$PDNS_DB_NAME" < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql
mysql -u "$PDNS_DB_USER" -h "$DB_IP" -p"$PDNS_DB_PASS" "$PDNS_DB_NAME" -e "ALTER TABLE records ADD COLUMN change_date INT DEFAULT NULL;"

# ==========================================
# TSIG KEY GENERATION (OPTIONAL)
# ==========================================
# Uncomment if you need TSIG for secure zone transfers
#pdnsutil generate-tsig-key transfer.key hmac-sha256
#TSIG_KEY=$(pdnsutil list-tsig-keys | grep -o 'transfer\.key.*' | cut -d' ' -f2)

# ==========================================
# POWERDNS CONFIGURATION
# ==========================================

cat <<EOF >/etc/powerdns/pdns.conf
# General parameters
master=yes                             # Master mode
slave=no                               # Explicitly disable slave mode
disable-axfr-rectify=no                # Enable auto updates of zones after modifications
daemon=yes                             # Daemon mode
guardian=yes                           # Protection against crashes
local-address=0.0.0.0

# Database configuration
launch=gmysql                          # Use MySQL backend
gmysql-host=$DB_IP
gmysql-user=$PDNS_DB_USER
gmysql-password=$PDNS_DB_PASS
gmysql-dbname=$PDNS_DB_NAME
gmysql-port=$DB_PORT
gmysql-dnssec=yes
gmysql-socket=                         # Important parameter to force TCP connection

# Serial auto-increment
default-soa-edit=INCREMENT-WEEKS       # Auto-increment serial on changes

# Security
allow-axfr-ips=$NS01_IP,$NS02_IP      # IP addresses of both BIND9 slaves
allow-notify-from=$NS01_IP,$NS02_IP   # Allow notifications from slaves
trusted-notification-proxy=$NS01_IP,$NS02_IP

# Logging
loglevel=4                             # Log detail level (0-9)
log-dns-queries=yes                    # Log queries

# Communication with slaves 
slave-cycle-interval=30                # Check slaves every 30 seconds
also-notify=$NS01_IP:53,$NS02_IP:53  # Notify BOTH slaves

# AXFR parameters
# BEWARE => only-notify conflicts with also-notify

# Cache poisoning protection
reuseport=yes
any-to-tcp=yes                         # Force ANY queries to TCP (harder to spoof)

# REST API
api=yes
api-key=$PDNS_API_KEY
webserver=yes
webserver-address=0.0.0.0
webserver-port=$PDNS_PORT
webserver-allow-from=127.0.0.1,$ANSIBLE_IP/32,$PDNS_IP/32
EOF

# ==========================================
# START SERVICE
# ==========================================
systemctl restart pdns
systemctl enable pdns

# ==========================================
# VERIFICATION
# ==========================================
echo "=== POWERDNS INSTALLATION VERIFICATION ==="

# Check service status
echo -e "\n1. Service status check..."
if systemctl is-active --quiet pdns; then
    echo "[SUCCESS] PowerDNS service is active"
else
    echo "[ERROR] PowerDNS service is not active"
    echo "Check logs: journalctl -u pdns -n 50"
    exit 1
fi

# Test API connectivity
echo -e "\n2. API connectivity test..."
sleep 2  # Wait for service to be fully ready

API_RESPONSE=$(curl -s -H "X-API-Key: $PDNS_API_KEY" "http://127.0.0.1:$PDNS_PORT/api/v1/servers/localhost" 2>/dev/null)

if echo "$API_RESPONSE" | grep -q '"type":"Server"'; then
    echo "[SUCCESS] PowerDNS API is accessible and functional"
    echo "API URL: http://127.0.0.1:$PDNS_PORT/api/v1"
else
    echo "[ERROR] PowerDNS API not accessible"
    echo "Response: $API_RESPONSE"
    echo "Check configuration in /etc/powerdns/pdns.conf"
    echo "Verify API key: $PDNS_API_KEY"
fi

# Test database connectivity
echo -e "\n3. Database connectivity test..."
if mysql -u "$PDNS_DB_USER" -h "$DB_IP" -p"$PDNS_DB_PASS" "$PDNS_DB_NAME" -e "SHOW TABLES;" | grep -q "domains\|records"; then
    echo "[SUCCESS] Database connectivity and schema verified"
else
    echo "[ERROR] Database connectivity or schema issue"
fi

# Show important information
echo -e "\n=== INSTALLATION COMPLETE ==="
echo "PowerDNS Master server is now ready for use with PPHOOK"
echo ""
echo "Configuration details:"
echo "  - Config file: /etc/powerdns/pdns.conf"
echo "  - Database: $PDNS_DB_NAME on $DB_IP"
echo "  - API endpoint: http://127.0.0.1:$PDNS_PORT/api/v1"
echo "  - API key: $PDNS_API_KEY"
echo "  - Logs: journalctl -u pdns"
echo ""
echo "Next steps:"
echo "  1. Create DNS zones using pdnsutil or PPHOOK"
echo "  2. Configure BIND9 slaves to transfer from this master"
echo "  3. Test zone transfers with: dig @$PDNS_IP AXFR domain.example"

# ==========================================
# SETUP AXFR MONITORING
# ==========================================
echo -e "\n4. Setting up AXFR monitoring..."

# Add cron job for AXFR transfer verification
if ! crontab -l 2>/dev/null | grep -q "monitor-axfr"; then
    (crontab -l 2>/dev/null; echo "*/5 * * * * $PROJECT_PATH/bash/monitor-axfr.sh") | crontab -
    echo "[SUCCESS] AXFR monitoring cron job added"
else
    echo "[INFO] AXFR monitoring cron job already exists"
fi

echo -e "\nPowerDNS installation completed successfully!"