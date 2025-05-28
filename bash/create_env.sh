#!/bin/bash

# Sourcer le fichier pour charger les variables dans l'environnement
source ../global_vars.sh

# Créer le .env avec substitution des variables (alternative sans envsubst)
eval "cat <<EOF
$(cat ../global_vars.sh)
EOF" > ../.env

# Chiffrer le fichier
cd ../
gpg --symmetric --cipher-algo AES256 --output .env.gpg .env

# Supprimer le fichier en clair
rm .env
