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
apt-get install python3 python3-pip python3-venv -y

# ==========================================
# CREATE VENV
# ==========================================
mkdir -p /opt/pphook
cd /opt/pphook
python3 -m venv pphook_venv
source pphook_venv/bin/activate

# ==========================================
# PIP DEPENDENCIES
# ==========================================
pip install requests configparser ipaddress datetime jinja2

# ==========================================
# CREATE CONFIG FILE
# ==========================================
cat <<EOF >/opt/pphook/config.ini
[phpipam]
api_url = http://$IPAM_IP/api
app_id = $IPAM_APP_ID
username = $IPAM_USERNAME
password = $IPAM_PASSWORD

[powerdns]
api_url = http://$PDNS_IP:$PDNS_PORT/api/v1
api_key = $PDNS_API_KEY
server = localhost

[email]
smtp_server = $SMTP_SERVER
smtp_port = $SMTP_PORT
from = $EMAIL_FROM
to = $EMAIL_TO
use_tls = $SMTP_USE_TLS

[validation]
hostname_pattern = $HOSTNAME_PATTERN
max_hostname_length = $MAX_HOSTNAME_LENGTH

[default]
domain = $DEFAULT_DOMAIN

[script]
check_interval = $CHECK_INTERVAL
last_check_file = $LAST_CHECK_FILE
mac_check_interval = $MAC_CHECK_INTERVAL
last_mac_check_file = $LAST_MAC_CHECK_FILE
EOF


# ==========================================
# CREATE SERVICE FILE
# ==========================================
cat <<EOF >/etc/systemd/system/pphook.service
[Unit]
Description=phpIPAM to PowerDNS synchronization service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pphook
Environment="PATH=/opt/pphook/pphook_venv/bin:/usr/bin:/bin"
ExecStart=/opt/pphook/pphook_venv/bin/python3 /opt/pphook/hook.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# ==========================================
# DEPLOYMENT
# ==========================================
# Copy Scripts
cp $PROJECT_PATH/python/pdns.py /opt/pphook/
chmod +x /opt/pphook/pdns.py

cp $PROJECT_PATH/python/phpipam.py /opt/pphook/
chmod +x /opt/pphook/phpipam.py

cp $PROJECT_PATH/python/hook.py /opt/pphook/
chmod +x /opt/pphook/hook.py

# Copy Email Templates Directory
mkdir -p /opt/pphook/templates/email/
cp $PROJECT_PATH/python/templates/email/email*.j2 /opt/pphook/templates/

# Create the directory for the last_check file
mkdir -p /var/lib/pphook


# ==========================================
# START SERVICE
# ==========================================
systemctl daemon-reload
systemctl enable pphook
systemctl restart pphook

# Check status
systemctl status pphook

# Check logs
tail -f /var/log/pphook.log
