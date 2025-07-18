# Dockerfile pour PPHOOK - Middleware phpIPAM-PowerDNS
FROM python:3.11-slim

# Métadonnées
LABEL maintainer="Intern n°38"
LABEL description="PPHOOK - phpIPAM/PowerDNS Hook Middleware"
LABEL version="1.0"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TZ=Europe/Paris

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Configuration timezone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Installation des dépendances Python
RUN pip install --no-cache-dir \
    requests \
    configparser \
    ipaddress \
    jinja2

# Création des répertoires de travail
RUN mkdir -p /opt/pphook/templates/email \
    /var/lib/pphook \
    /var/log

# Répertoire de travail
WORKDIR /opt/pphook

# Copie des fichiers Python principaux depuis l'arborescence parent
COPY python/hook.py .
COPY python/pdns.py .
COPY python/phpipam.py .

# Copie des templates email
COPY python/templates/email/*.j2 ./templates/email/

# Copie du script de reset timestamp (interne au conteneur)
COPY bash/reset_timestamp.sh .
RUN chmod +x reset_timestamp.sh

# Configuration des permissions
RUN chmod +x hook.py pdns.py phpipam.py

# Healthcheck
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import os; exit(0 if os.path.exists('/var/lib/pphook/last_check') else 1)"

# Point d'entrée
ENTRYPOINT ["python3", "hook.py", "--daemon"]
