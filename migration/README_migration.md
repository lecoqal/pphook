# Migration des logiciels phpipam et PowerDNS

## Contexte
L'infrastructure du réseau lycée possède actuellement des versions anciennes des logiciels phpipam et PowerDNS.
A ce jour, de nouvelles fonctionnalités et corrections de bugs existent dans les dernières versions.
Il est donc très interresant de migrer des anciennes versions vers les nouvelles.

## Problématique
Seulement, la migration comporte une certaine problématique liée aux bases de données.
En effet, il y a des divergences dans les schemas entre les anciennes et dernières versions des logiciels. Des tables ou colonnes manquantes,
des formats de type de colonne modifiés, etc...
Ces divergences cause des problèmes de compatibilité et donc des erreurs.

## Import/Export des bases
Grâce au fichier migration_tool, vous pourez importer et exporter les tables des bases de données que vous souhaitez. Vous aurez une succesion
de choix et d'input de variables à renseigner.
Par exemple:
``` bash
source migration_tool.sh   # Execution du script
1) Export
2) Import
Votre choix:
1) phpipam
2) PowerDNS
3) Les deux

IP de la BDD:
nom de la base
username de la base:
mdp de la base:

Si Import alors:
IP du HOOK:
User du HOOK:
```

La partie du Hook à renseigner servira au process de reset_timestamp, qui permet in fine, d'activer la vérification de TOUTES les entrées de phpipam par
le logiciel PPHook.

## Plan d'action

### PHPIPAM
phpipam possède un système automatique de migration de versions avec la gestion des différences entre schema de bases.
En effet, ce système de migration est cumulatif et non séquentielle, ce qui permet donc de passer d'une vieille version à la dernière
sans avoir à installer les versions intermédiaires. Mais cela reste conseiller de faire un dump de la base avant migration, ou une snapshot de la VM.

### POWERDNS
PowerDNS fonctionne différemment, elle n'a pas de système de migration automatique, tout est manuel. Il faut donc choisir entre deux méthodes.

#### Migration Séquentielle (Plus sûre mais plus lente)
Cette méthode nécessite d'installer des sauts de version 1 par 1. Par exemple:
```
4.0.3 → 4.1.0
4.1.0 → 4.2.0
4.2.0 → 4.3.0
4.3.0 → 4.4.0
4.4.0 → 4.5.0
4.5.0 → 4.6.0
4.6.0 → 4.7.0
4.7.0 → 4.8.0
4.8.0 → 4.9.0 (latest)
```

Avant cela, il faudra:
1) Arrêter le service
2) Sauvegarder la configuration et faire un dump de la base
3) Mettre à jour les paquets
``` bash
apt update
apt upgrade -y pdns-server pdns-backend-mysql
```
4) Faire la migration de version
5) Vérifier la configuration

#### Migration Directe
L'idée de cette méthode est de passe de l'ancienne version directement à la dernière. Pour cela, il faut au préalable faire une analyse des
schemas des bases.
L'analyse des diverges entre base de données est possible à l'aide de mysqldiff ou de pt-schema-diff.
Par la suite, il faut:
- Créer un environnement de préproduction en installant la version actuellement en production de PowerDNS (4.0.3).
- Importer les données de production dans cette maquette
- Faire la modification de la base de donnée de préproduction. Grâce à l'analyse des différences, il ne reste plus qu'à faire les modifications nécessaires.
- Faire une série de tests => Vérifier que l'on peut toujours créer des users, des entrées, des enregistrements et zones DNS, etc...
- Si tout vas bien avec ces modifications, exporter les bases modifiées.
- Créer un environnement de préproduction en installant les dernières versions des logiciels phpipam (1.7.3) et de PowerDNS (4.7.3).
- Importer les données des bases modifiées.
- Faire la même série de tests.
- Migrer la préproduction vers la production


## Guide Migration Séquentielle de PowerDNS

4.0.3 → 4.1.0
``` sql
-- Migration 4.0.3 vers 4.1.0
-- Ajout de nouvelles colonnes pour les métadonnées

ALTER TABLE records ADD COLUMN disabled BOOLEAN DEFAULT FALSE;
ALTER TABLE records ADD COLUMN ordername VARCHAR(255);
ALTER TABLE records ADD COLUMN auth BOOLEAN DEFAULT TRUE;

-- Ajout d'index pour les performances
CREATE INDEX records_name_type_idx ON records(name, type);
CREATE INDEX records_domain_id_ordername_idx ON records(domain_id, ordername);
```

4.1.0 → 4.2.0
``` sql
-- Migration 4.1.0 vers 4.2.0
-- Modifications pour l'amélioration des performances

ALTER TABLE records MODIFY COLUMN content TEXT;
ALTER TABLE records ADD COLUMN changed_date INT DEFAULT NULL;

-- Mise à jour des index
DROP INDEX IF EXISTS records_name_type_idx;
CREATE INDEX records_name_type_idx ON records(name, type);
CREATE INDEX records_domain_id_idx ON records(domain_id);
```

4.2.0 → 4.3.0
``` sql
-- Migration 4.2.0 vers 4.3.0
-- Ajout du support pour les nouveaux types d'enregistrements

-- Pas de changements majeurs de schéma pour cette version
-- Principalement des améliorations de performance internes

4.3.0 → 4.4.0
-- Migration 4.3.0 vers 4.4.0
-- Améliorations du schéma pour les performances

ALTER TABLE domains ADD COLUMN options TEXT;
ALTER TABLE domains ADD COLUMN catalog VARCHAR(255);

-- Index pour le catalog
CREATE INDEX domains_catalog_idx ON domains(catalog);
```

4.4.0 → 4.5.0
``` sql
-- Migration 4.4.0 vers 4.5.0
-- Support amélioré pour les métadonnées

CREATE TABLE IF NOT EXISTS domainmetadata (
    id INT AUTO_INCREMENT,
    domain_id INT NOT NULL,
    kind VARCHAR(32),
    content TEXT,
    PRIMARY KEY (id),
    KEY domainidindex (domain_id)
);

-- Index pour les performances
CREATE INDEX domainmetadata_domain_id_idx ON domainmetadata(domain_id);
```

4.5.0 → 4.6.0
``` sql
-- Migration 4.5.0 vers 4.6.0
-- Améliorations de la gestion des commentaires

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT,
    domain_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL,
    modified_at INT NOT NULL,
    account VARCHAR(40) DEFAULT NULL,
    comment VARCHAR(65535) NOT NULL,
    PRIMARY KEY (id),
    KEY comments_domain_id_idx (domain_id),
    KEY comments_name_type_idx (name, type),
    KEY comments_order_idx (domain_id, modified_at)
);
```

4.6.0 → 4.7.0
``` sql
-- Migration 4.6.0 vers 4.7.0
-- Optimisations pour les grandes bases de données

-- Amélioration des index existants
ALTER TABLE records ADD INDEX records_name_type_idx (name(40), type);
ALTER TABLE records ADD INDEX records_domain_id_ordername_idx (domain_id, ordername);

-- Optimisation des requêtes
OPTIMIZE TABLE records;
OPTIMIZE TABLE domains;
```

4.7.0 → 4.8.0
``` sql
-- Migration 4.7.0 vers 4.8.0
-- Support amélioré pour les API et les statistiques

-- Ajout de colonnes pour les statistiques
ALTER TABLE domains ADD COLUMN options TEXT;
ALTER TABLE domains ADD COLUMN catalog VARCHAR(255);

-- Mise à jour des contraintes
ALTER TABLE records MODIFY COLUMN auth BOOLEAN DEFAULT TRUE;
```

4.8.0 → 4.9.0 (latest)
``` sql
-- Migration 4.8.0 vers 4.9.0
-- Dernières améliorations et corrections

-- Optimisation finale des index
CREATE INDEX IF NOT EXISTS records_domain_id_name_idx ON records(domain_id, name);
CREATE INDEX IF NOT EXISTS records_domain_id_type_idx ON records(domain_id, type);

-- Nettoyage des données obsolètes
DELETE FROM records WHERE content = '';
```