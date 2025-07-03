#!/bin/bash

ZONE=$1
NS_IP=$2
NS_HOSTNAME=$3

if [ $# -ne 3 ]; then
    echo "Usage: $0 <zone> <ns_ip> <ns_hostname>"
    echo "Exemple: $0 example.com 192.168.1.10 ns.example.com"
    exit 1
fi

SERIAL=$(date +%Y%m%d%H)

# === ZONE DIRECTE ===
echo "Création zone directe $ZONE"

pdnsutil create-zone "$ZONE"
pdnsutil set-kind "$ZONE" MASTER

# SOA avec le bon hostname NS
pdnsutil replace-rrset "$ZONE" '' SOA 3600 "$NS_HOSTNAME. admin.$ZONE. $SERIAL 10800 3600 604800 3600"

# NS avec le hostname du serveur NS
pdnsutil replace-rrset "$ZONE" '' NS 3600 "$NS_HOSTNAME."

# A record pour le serveur NS (seulement si le NS est dans la zone)
if [[ "$NS_HOSTNAME" == *"$ZONE"* ]]; then
    # Extraire le nom d'hôte sans le domaine
    NS_NAME=$(echo "$NS_HOSTNAME" | sed "s/\.$ZONE//")
    echo "Ajout enregistrement A pour $NS_NAME dans $ZONE"
    pdnsutil replace-rrset "$ZONE" "$NS_NAME" A 3600 "$NS_IP"
fi

# === ZONE INVERSE ===
IFS='.' read -ra IP <<< "$NS_IP"
REVERSE_ZONE="${IP[2]}.${IP[1]}.${IP[0]}.in-addr.arpa"

echo "Création zone inverse $REVERSE_ZONE"

pdnsutil create-zone "$REVERSE_ZONE"
pdnsutil set-kind "$REVERSE_ZONE" MASTER

# SOA inverse avec le bon hostname NS
pdnsutil replace-rrset "$REVERSE_ZONE" '' SOA 3600 "$NS_HOSTNAME. admin.$REVERSE_ZONE. $SERIAL 10800 3600 604800 3600"

# NS inverse avec le hostname du serveur NS
pdnsutil replace-rrset "$REVERSE_ZONE" '' NS 3600 "$NS_HOSTNAME."

# PTR pour le serveur NS lui-même
LAST_OCTET="${IP[3]}"
pdnsutil replace-rrset "$REVERSE_ZONE" "$LAST_OCTET" PTR 3600 "$NS_HOSTNAME."

echo "Terminé :"
echo "  - Zone directe : $ZONE"
echo "  - Zone inverse : $REVERSE_ZONE"
echo "  - Serveur NS : $NS_HOSTNAME ($NS_IP)"

# === VÉRIFICATION ===
echo ""
echo "=== Vérification des zones créées ==="
echo "Zone directe $ZONE :"
pdnsutil list-zone "$ZONE"
echo ""
echo "Zone inverse $REVERSE_ZONE :"
pdnsutil list-zone "$REVERSE_ZONE"
