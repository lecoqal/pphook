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
rm global_vars.sh

echo "Souhaitez-vous créer un fichier de passphrase? o/N"
read response

if [ $response = "o" ]
then
    echo "Entrez à nouveau votre mot de passe"
    read mdp
    echo "$mdp" > .gpg_passphrase
    chmod 600 .gpg_passphrase
fi

