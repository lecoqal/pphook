#!/bin/bash

##############################
#    VARIABLES GLOBALES      #
##############################

# Réseau
DOMAIN=""

# Base de données
DB_HOST=""
DB_IP=""
DB_PORT="3306"

# PowerDNS
PDNS_HOST=""
PDNS_IP=""
PDNS_PORT="8081"
PDNS_API_KEY=""
PDNS_DB_NAME=""
PDNS_DB_USER=""
PDNS_DB_PASS=""
PDNS_VERSION="4.7.0"
PDNS_API_URL="http://$PDNS_IP:$PDNS_PORT/api/v1"

# PowerDNS Admin
PDNSADMIN_DB_NAME=""
PDNSADMIN_DB_USER=""
PDNSADMIN_DB_PASS=""
PDNSADMIN_SECRET_KEY=""
PDNSADMIN_API_KEY=""

# phpIPAM
IPAM_HOST=""
IPAM_IP=""
IPAM_API_URL="http://${IPAM_IP}/api"
IPAM_APP_ID=""
IPAM_API_KEY=""
IPAM_DB_NAME=""
IPAM_DB_USER=""
IPAM_DB_PASS=""
IPAM_USERNAME=""
IPAM_PASSWORD=""
PHPIPAM_VERSION="1.7"

# DHCP et Ansible
DHCP_HOST=""
DHCP_IP=""
ANSIBLE_HOST=""
ANSIBLE_IP=""

# DNS
NS01_HOST=""
NS01_IP=""
NS02_HOST=""
NS02_IP=""

# Email
SMTP_SERVER=""
SMTP_PORT="25"
EMAIL_FROM=""
EMAIL_TO=""
SMTP_USE_TLS="False"

# Validation
HOSTNAME_PATTERN="^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$"
MAX_HOSTNAME_LENGTH="63"

# Hook
CHECK_INTERVAL="60"
LAST_CHECK_FILE="/var/lib/pphook/last_check"
HOOK_HOST=$ANSIBLE_HOST
HOOK_IP=$ANSIBLE_IP

# Divers
PROJECT_PATH=""
DEFAULT_DOMAIN=""
TIMEZONE="Europe/Paris"
LOG_LEVEL="INFO"
