#!/bin/bash

# Script de déploiement PPHOOK pour Docker Swarm
# Compatible CI/CD GitLab et mode manuel

set -e

echo "=== DÉPLOIEMENT PPHOOK DOCKER ==="

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Fonction de log
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Variables par défaut
STACK_NAME="pphook"
COMPOSE_FILE="docker-compose.yml"

# Fonction pour créer un secret Docker si il n'existe pas
create_secret() {
    local secret_name="$1"
    local secret_value="$2"
    
    if docker secret ls --format "{{.Name}}" | grep -q "^${secret_name}$"; then
        log_warn "Secret ${secret_name} existe déjà"
    else
        echo "$secret_value" | docker secret create "$secret_name" -
        log_info "Secret ${secret_name} créé"
    fi
}

# Fonction pour configuration manuelle (mode interactif)
configure_secrets_manual() {
    log_info "Configuration manuelle des secrets Docker..."
    
    # phpIPAM
    echo ""
    echo "=== Configuration phpIPAM ==="
    read -p "URL API phpIPAM: " PHPIPAM_URL
    read -p "App ID phpIPAM: " PHPIPAM_APP_ID
    read -p "Username phpIPAM: " PHPIPAM_USERNAME
    read -s -p "Password phpIPAM: " PHPIPAM_PASSWORD
    echo ""
    
    # PowerDNS
    echo ""
    echo "=== Configuration PowerDNS ==="
    read -p "URL API PowerDNS: " POWERDNS_URL
    read -s -p "Clé API PowerDNS: " POWERDNS_API_KEY
    echo ""
    
    # Email
    echo ""
    echo "=== Configuration Email ==="
    read -p "Serveur SMTP: " SMTP_SERVER
    read -p "Port SMTP: " SMTP_PORT
    read -p "Email expéditeur: " EMAIL_FROM
    read -p "Email destinataire: " EMAIL_TO
    read -p "Email générique (optionnel): " GENERIC_EMAIL
    
    # Validation
    echo ""
    echo "=== Configuration Validation ==="
    read -p "Pattern hostname: " HOSTNAME_PATTERN
    read -p "Longueur max hostname: " MAX_HOSTNAME_LENGTH
    
    # Script
    echo ""
    echo "=== Configuration Script ==="
    read -p "Intervalle de vérification en secondes: " CHECK_INTERVAL
    
    # Créer les secrets
    create_secrets_from_vars
}

# Fonction pour configuration CI/CD (depuis variables d'environnement)
configure_secrets_cicd() {
    log_info "Configuration depuis les variables CI/CD..."
    
    # Vérifier que toutes les variables sont présentes
    local required_vars=(
        "PHPIPAM_URL" "PHPIPAM_APP_ID" "PHPIPAM_USERNAME" "PHPIPAM_PASSWORD"
        "POWERDNS_URL" "POWERDNS_API_KEY"
        "SMTP_SERVER" "SMTP_PORT" "EMAIL_FROM" "EMAIL_TO"
        "HOSTNAME_PATTERN" "MAX_HOSTNAME_LENGTH" "CHECK_INTERVAL"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "Variable d'environnement manquante: $var"
            return 1
        fi
    done
    
    log_info "Toutes les variables CI/CD sont présentes"
    
    # GENERIC_EMAIL est optionnel
    GENERIC_EMAIL=${GENERIC_EMAIL:-""}
    
    # Créer les secrets
    create_secrets_from_vars
}

# Fonction pour créer les secrets depuis les variables
create_secrets_from_vars() {
    log_info "Création des secrets Docker..."
    
    create_secret "phpipam_url" "$PHPIPAM_URL"
    create_secret "phpipam_app_id" "$PHPIPAM_APP_ID"
    create_secret "phpipam_username" "$PHPIPAM_USERNAME"
    create_secret "phpipam_password" "$PHPIPAM_PASSWORD"
    
    create_secret "powerdns_url" "$POWERDNS_URL"
    create_secret "powerdns_api_key" "$POWERDNS_API_KEY"
    
    create_secret "smtp_server" "$SMTP_SERVER"
    create_secret "smtp_port" "$SMTP_PORT"
    create_secret "email_from" "$EMAIL_FROM"
    create_secret "email_to" "$EMAIL_TO"
    create_secret "generic_email" "$GENERIC_EMAIL"
    
    create_secret "hostname_pattern" "$HOSTNAME_PATTERN"
    create_secret "max_hostname_length" "$MAX_HOSTNAME_LENGTH"
    create_secret "check_interval" "$CHECK_INTERVAL"
    
    log_info "Tous les secrets ont été créés !"
}

# Fonction pour détecter le mode (CI/CD vs manuel)
configure_secrets() {
    if [[ -n "$CI" || -n "$GITLAB_CI" ]]; then
        log_info "Détection mode CI/CD"
        configure_secrets_cicd
    else
        log_info "Mode manuel détecté"
        configure_secrets_manual
    fi
}

# Fonction pour construire l'image
build_image() {
    log_info "Construction de l'image Docker..."
    docker build -t pphook:1.0 .
    log_info "Image construite avec succès !"
}

# Fonction pour déployer le stack
deploy_stack() {
    log_info "Déploiement du stack Docker Swarm..."
    
    if ! docker node ls >/dev/null 2>&1; then
        log_error "Docker Swarm n'est pas initialisé"
        log_info "Initialisation de Docker Swarm..."
        docker swarm init
    fi
    
    docker stack deploy -c "$COMPOSE_FILE" "$STACK_NAME"
    log_info "Stack déployé avec succès !"
}

# Fonction pour afficher le statut
show_status() {
    log_info "Statut du déploiement:"
    echo ""
    echo "=== Services ==="
    docker stack services "$STACK_NAME"
    echo ""
    echo "=== Logs (dernières 20 lignes) ==="
    docker service logs --tail 20 "${STACK_NAME}_pphook" 2>/dev/null || log_warn "Pas encore de logs disponibles"
}

# Fonction pour nettoyer (optionnel)
cleanup() {
    log_warn "Suppression du stack PPHOOK..."
    docker stack rm "$STACK_NAME"
    log_info "Stack supprimé !"
}

# Fonction pour reset timestamp (utilitaire)
reset_timestamp() {
    log_info "Reset du timestamp PPHOOK..."
    docker exec $(docker ps -q -f name="${STACK_NAME}_pphook") /opt/pphook/reset_timestamp.sh
    log_info "Timestamp reset effectué !"
}

# Menu principal
case "${1:-deploy}" in
    "configure")
        configure_secrets
        ;;
    "build")
        build_image
        ;;
    "deploy")
        configure_secrets
        build_image
        deploy_stack
        show_status
        ;;
    "status")
        show_status
        ;;
    "logs")
        docker service logs -f "${STACK_NAME}_pphook"
        ;;
    "reset")
        reset_timestamp
        ;;
    "cleanup")
        cleanup
        ;;
    *)
        echo "Usage: $0 {configure|build|deploy|status|logs|reset|cleanup}"
        echo ""
        echo "  configure  - Configure les secrets Docker"
        echo "  build      - Construit l'image Docker"
        echo "  deploy     - Déploiement complet (configure + build + deploy)"
        echo "  status     - Affiche le statut du déploiement"
        echo "  logs       - Suit les logs en temps réel"
        echo "  reset      - Reset le timestamp PPHOOK"
        echo "  cleanup    - Supprime le stack complet"
        echo ""
        echo "Mode CI/CD: défini les variables d'environnement"
        echo "Mode manuel: utilise le mode interactif"
        exit 1
        ;;
esac

log_info "Opération terminée !"
