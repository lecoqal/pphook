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
apt install -y git python3-pip python3-dev libsasl2-dev libldap2-dev libssl-dev libmariadb-dev
apt install npm -y
npm install --global yarn
apt install python3.11-venv -y
apt install -y nginx curl
apt install pkg-config -y
apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl -y

# ==========================================
# DATABASE CONFIG
# ==========================================
mysql -u "$PDNS_DB_USER" -h "$DB_IP" -p"$PDNS_DB_PASS" "$PDNS_DB_NAME" < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql
mysql -u "$PDNS_DB_USER" -h "$DB_IP" -p"$PDNS_DB_PASS" "$PDNS_DB_NAME" -e "ALTER TABLE records ADD COLUMN change_date INT DEFAULT NULL;"

# ==========================================
# TSIG KEY GENERATION
# ==========================================
#pdnsutil generate-tsig-key transfer.key hmac-sha256    # Generate a TSIG key
#TSIG_KEY = $(pdnsutil list-tsig-keys)                  # Retrieve the key into a variable

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

# ==========================================
# GET PDNS CLONE
# ==========================================
cd /opt
git clone https://github.com/ngoduykhanh/PowerDNS-Admin.git
cd PowerDNS-Admin

# ==========================================
# CREATE VIRTUAL ENVIRONMENT
# ==========================================
mkdir pdns_venv
python3 -m venv pdns_venv/
source pdns_venv/bin/activate

# ==========================================
# PIP DEPENDENCIES
# ==========================================
pip install xmlsec
pip install wheel
pip install pymysql
sed -i 's/^psycopg2==.*$/psycopg2-binary==2.9.10/' requirements.txt
sed -i 's/^SQLAlchemy==.*$/SQLAlchemy<2.0/' requirements.txt
pip install -r requirements.txt
cd $PROJECT_PATH

# ==========================================
# CREATE CONFIG.PY
# ==========================================
cat <<EOF >/opt/PowerDNS-Admin/configs/config.py
#!/bin/sh

import os

# ------------------------------
# SECURITY SETTINGS
# ------------------------------
SECRET_KEY = '$PDNSADMIN_SECRET_KEY'

# ------------------------------
# SQLAlchemy / Database
# ------------------------------
SQLALCHEMY_TRACK_MODIFICATIONS = False
SESSION_TYPE = 'sqlalchemy'
SQLALCHEMY_DATABASE_URI = 'mysql://{}:{}@{}:{}/{}'.format(
        '$PDNSADMIN_DB_USER',
        '$PDNSADMIN_DB_PASS',
        '$DB_IP',
        $DB_PORT,
        '$PDNSADMIN_DB_NAME'
)

# ------------------------------
# REST API SETTINGS
# ------------------------------
API_ENABLED = True
API_AUTHENTICATION_REQUIRED = True
API_TOKEN_EXPIRATION = 3600  # Token validity duration in seconds

# ------------------------------
# PowerDNS SETTINGS
# ------------------------------
PDNS_STATS_URL = 'http://127.0.0.1:$PDNS_PORT/'  # PowerDNS stats API URL
PDNS_API_KEY = '$PDNS_API_KEY'  # PowerDNS API key (configured in pdns.conf)
PDNS_VERSION = '$PDNS_VERSION'
PDNS_API_URL = f"{PDNS_STATS_URL}api/v1"

# ------------------------------
# OPTIONAL : Logging
# ------------------------------
LOG_LEVEL = 'INFO'
LOG_FILE = 'logs/pdnsadmin.log'

# ------------------------------
# OPTIONAL : Session
# ------------------------------
SESSION_TYPE = 'filesystem'

# ------------------------------
# PDNS-ADMIN : Authentication
# ------------------------------
AUTH_TYPE = 'LOCAL_AUTH'

# ------------------------------
# PDNSADMIN DATABASE
# ------------------------------
SQLA_DB_USER = '$PDNSADMIN_DB_USER'
SQLA_DB_PASSWORD = '$PDNSADMIN_DB_PASS'
SQLA_DB_HOST = '$DB_IP'
SQLA_DB_NAME = '$PDNSADMIN_DB_NAME'
EOF

# ==========================================
# CREATE DEFAULT ADMIN USER
# ==========================================
cat <<EOF >/opt/PowerDNS-Admin/create_admin.py
#!/usr/bin/env python3
"""
Script to create an administrator user for PowerDNS-Admin
"""

import os
import sys

# Add PowerDNS-Admin directory to path
sys.path.insert(0, '/opt/PowerDNS-Admin')

# Import necessary modules
from powerdnsadmin import create_app
from powerdnsadmin.models.user import User
from powerdnsadmin.models.role import Role
from powerdnsadmin.models import db

# Configuration
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'
ADMIN_EMAIL = 'admin@example.com'

# Create application
app = create_app()

# Use application context
with app.app_context():
    print("Checking database connection...")

    try:
        # Check connection with a simple query
        db.session.execute("SELECT 1")
        print("[SUCCESS] Database connection successful")
    except Exception as e:
        print(f"[ERROR] Database connection error: {e}")
        sys.exit(1)

    # Check if admin user already exists
    print(f"\nChecking user '{ADMIN_USERNAME}'...")

    admin_user = User.query.filter(User.username == ADMIN_USERNAME).first()

    if admin_user:
        print(f"[SUCCESS] User '{ADMIN_USERNAME}' already exists")
        print("To reset password, run with --force")
    else:
        print(f"Creating user '{ADMIN_USERNAME}'...")

        # Get Administrator role
        admin_role = Role.query.filter(Role.name == 'Administrator').first()

        if not admin_role:
            print("[ERROR] 'Administrator' role not found. Please run 'flask db upgrade' first.")
            sys.exit(1)

        # Create admin user
        admin_user = User(
            username=ADMIN_USERNAME,
            plain_text_password=ADMIN_PASSWORD,
            email=ADMIN_EMAIL,
            firstname='Admin',
            lastname='User',
            role_id=admin_role.id,
            confirmed=True
        )

        # Save user
        try:
            admin_user.create_local_user()
            print(f"[SUCCESS] User '{ADMIN_USERNAME}' created successfully")
            print(f"  Email: {ADMIN_EMAIL}")
            print(f"  Password: {ADMIN_PASSWORD}")
            print("\n!!! Don't forget to change the password after first login !!!")
        except Exception as e:
            print(f"[ERROR] Error creating user: {e}")
            sys.exit(1)

    print("\nFinal verification...")
    user_count = User.query.count()
    print(f"Total number of users: {user_count}")

    if user_count > 0:
        print("\n[SUCCESS] Configuration successful!")
    else:
        print("\n[ERROR] No users found - something failed")
EOF

# ==========================================
# INITIALIZING PDNS API PARAMETERS
# ==========================================
cat <<'EOF' >/opt/PowerDNS-Admin/init_settings.py
#!/usr/bin/env python3
"""
Script to initialize API parameters in database
"""
from powerdnsadmin import create_app
from powerdnsadmin.models.setting import Setting
from powerdnsadmin.models import db
import os

# Get environment variables defined by main script
PDNS_PORT = os.environ.get('PDNS_PORT', '8081')
PDNS_API_KEY = os.environ.get('PDNS_API_KEY', '')
PDNS_VERSION = os.environ.get('PDNS_VERSION', '4.7.0')

app = create_app()
with app.app_context():
    # Function to update or create a setting
    def update_setting(name, value):
        setting = Setting.query.filter_by(name=name).first()
        if not setting:
            print(f"Creating setting '{name}' with value '{value}'")
            setting = Setting(name=name, value=value)
            db.session.add(setting)
        else:
            print(f"Updating setting '{name}': '{setting.value}' -> '{value}'")
            setting.value = value
    
    # Update API settings
    update_setting('pdns_api_url', f'http://127.0.0.1:{PDNS_PORT}/api/v1')
    update_setting('pdns_stats_url', f'http://127.0.0.1:{PDNS_PORT}')
    update_setting('pdns_api_key', PDNS_API_KEY)
    update_setting('pdns_version', PDNS_VERSION)
    
    # Save changes
    db.session.commit()
    
    # Verify settings after update
    print("\nVerifying settings after update:")
    for name in ['pdns_api_url', 'pdns_stats_url', 'pdns_api_key', 'pdns_version']:
        setting = Setting.query.filter_by(name=name).first()
        if setting:
            print(f"{name}: {setting.value}")
        else:
            print(f"{name}: NOT DEFINED")
EOF

# ==========================================
# CONFIGURATION TEST
# ==========================================

echo "=== CONFIGURATION VERIFICATION ==="

# Go to PowerDNS-Admin directory
cd /opt/PowerDNS-Admin

# Initialize/Upgrade database
echo -e "\n2. Database initialization..."
export FLASK_APP=powerdnsadmin/__init__.py
flask db upgrade

# Create admin user
echo -e "\n3. Creating admin user..."
python3 create_admin.py

# Initialize API settings in database
echo -e "\n4. Initializing API settings..."
export PDNS_PORT=$PDNS_PORT
export PDNS_API_KEY=$PDNS_API_KEY
export PDNS_VERSION=$PDNS_VERSION
python3 init_settings.py

# Build assets
echo -e "\n5. Building assets..."
yarn install --pure-lockfile
flask assets build

# ==========================================
# CREATE SERVICE FILE
# ==========================================
cat <<EOF >/etc/systemd/system/powerdns-admin.service
[Unit]
Description=PowerDNS-Admin WSGI Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/PowerDNS-Admin
Environment="PATH=/opt/PowerDNS-Admin/pdns_venv/bin"
Environment="FLASK_CONFIG=/opt/PowerDNS-Admin/configs/config.py"
Environment="SQLALCHEMY_SILENCE_UBER_WARNING=1"

ExecStart=/opt/PowerDNS-Admin/pdns_venv/bin/gunicorn \
  --workers 4 \
  --bind 127.0.0.1:8000 \
  --timeout 120 \
  powerdnsadmin:create_app()

Restart=on-failure
RestartSec=5s

# Enhanced security directives
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Modify permissions
chown -R www-data:www-data /opt/PowerDNS-Admin

# ==========================================
# CREATE NGINX SITE
# ==========================================

cat <<EOF >/etc/nginx/sites-available/powerdns-admin
server {
    listen 80;
    server_name $PDNS_IP;

    access_log /var/log/nginx/pdns-admin.access.log;
    error_log /var/log/nginx/pdns-admin.error.log;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static {
        alias /opt/PowerDNS-Admin/powerdnsadmin/static;
        expires 30d;
    }
}
EOF

ln -s /etc/nginx/sites-available/powerdns-admin /etc/nginx/sites-enabled/

echo -e "\n6. Starting NGINX service..."
systemctl restart nginx

 ###############################################################################################
######################################## PDNS ADMIN LOGS ####################################
### NGINX LOGS => /var/log/nginx/pdns-admin.access.log AND /var/log/nginx/pdns-admin.error.log ###
### systemd LOGS => journalctl -u powerdns-admin                                              ###
 ###############################################################################################

# ==========================================
# START SERVICE
# ==========================================
echo -e "\n7. Starting powerdnsadmin service..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable powerdns-admin
systemctl start powerdns-admin

# Wait a bit for service to start
sleep 3

# Check service status
echo -e "\n8. Status verification..."
if systemctl is-active --quiet powerdns-admin; then
    echo "[SUCCESS] powerdns-admin service is active"

    # Test HTTP connection
    echo -e "\n9. HTTP test..."
    if curl -s http://localhost:8000 | grep -q "login\|Sign"; then
        echo "[SUCCESS] Login page accessible at http://$PDNS_IP"
        echo -e "\n=== CONFIGURATION COMPLETED SUCCESSFULLY ==="
        echo "You can now log in with:"
        echo "  Username: admin"
        echo "  Password: admin"
        echo ""
        echo "Don't forget to change this password after first login!"
    else
        echo "[ERROR] Login page not accessible"
        echo "Check logs: journalctl -u powerdns-admin -n 50"
    fi
else
    echo "[ERROR] powerdns-admin service is not active"
    echo "Check logs: journalctl -u powerdns-admin -n 50"
fi

# ==========================================
# API CHECK
# ==========================================
echo -e "\n10. PowerDNS API test..."
curl -s -H "X-API-Key: $PDNS_API_KEY" http://127.0.0.1:$PDNS_PORT/api/v1/servers/localhost > /tmp/pdns_api_test.json
if grep -q "version" /tmp/pdns_api_test.json; then
    echo "[SUCCESS] PowerDNS API accessible and functional"
    rm /tmp/pdns_api_test.json
else
    echo "[ERROR] PowerDNS API not accessible"
    echo "Check configuration in /etc/powerdns/pdns.conf"
fi

# IMPORTANT INFORMATION REMINDER
# ==========================================
echo -e "\n=== IMPORTANT INFORMATION ==="
echo "- Access IP: http://$PDNS_IP"
echo "- Configuration: /opt/PowerDNS-Admin/configs/config.py"
echo "- Main logs: journalctl -u powerdns-admin"
echo "- Nginx logs: /var/log/nginx/pdns-admin.error.log"
echo "- PowerDNS API URL: http://127.0.0.1:$PDNS_PORT/api/v1"
echo "- PowerDNS API Key: $PDNS_API_KEY"

### CRON AXFR TRANSFER VERIFICATION ###

(crontab -l 2>/dev/null; echo "*/5 * * * * $PROJECT_PATH/bash/monitor-axfr.sh") | crontab -
