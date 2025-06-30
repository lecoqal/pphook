#!/bin/bash

ZONE=$1
NS_IP=$2

if [ $# -ne 2 ]; then
    echo "Usage: $0 <zone> <ns_ip>"
    echo "Exemple: $0 example.com 192.168.1.10"
    exit 1
fi

SERIAL=$(date +%Y%m%d%H)

# === ZONE DIRECTE ===
echo "Création zone $ZONE"

pdnsutil create-zone "$ZONE"
pdnsutil change-zone-type "$ZONE" MASTER

# SOA
pdnsutil replace-rrset "$ZONE" '' SOA 3600 "ns.$ZONE. admin.$ZONE. $SERIAL 10800 3600 604800 3600"

# NS
pdnsutil replace-rrset "$ZONE" '' NS 3600 "ns.$ZONE."

# A du NS
pdnsutil replace-rrset "$ZONE" "ns" A 3600 "$NS_IP"

# === ZONE INVERSE ===
IFS='.' read -ra IP <<< "$NS_IP"
REVERSE_ZONE="${IP[2]}.${IP[1]}.${IP[0]}.in-addr.arpa"

echo "Création zone inverse $REVERSE_ZONE"

pdnsutil create-zone "$REVERSE_ZONE"
pdnsutil change-zone-type "$REVERSE_ZONE" MASTER

# SOA inverse
pdnsutil replace-rrset "$REVERSE_ZONE" '' SOA 3600 "ns.$ZONE. admin.$ZONE. $SERIAL 10800 3600 604800 3600"

# NS inverse
pdnsutil replace-rrset "$REVERSE_ZONE" '' NS 3600 "ns.$ZONE."

echo "Terminé : $ZONE et $REVERSE_ZONE"
