# Registre officiel de Cassandra

Le magasin de modules de [Cassandra](https://github.com/Marplestrange) : ce dépôt est la **source de vérité**. Ce qu'il contient, signé, est ce que l'App Store de Cassandra propose.

- **Pour installer un module** : dans Cassandra, menu avatar › App Store › Registre.
- **Pour publier un module** : voir [CONTRIBUER.md](CONTRIBUER.md).
- **Pour comprendre la confiance** : voir [GOUVERNANCE.md](GOUVERNANCE.md) et [SECURITE.md](SECURITE.md).

## Comment ça tient
```
cles/        les clés PUBLIQUES racine (principale et secours) : la racine de confiance, la même que celle embarquée dans l'application
editeurs/    les éditeurs dont l'identité est vérifiée (leur clé publique)
revocations.toml   ce qui est retiré, et pourquoi
docs/        ce qui est PUBLIÉ (servi tel quel) : index.json, index.json.sig, la vitrine, modules/<id>/<id>-<version>.cmod
outils/registre.py   contrôle le dépôt et publie l'index signé (hors ligne, avec la clé privée racine)
```

Un module est une archive `.cmod` **signée** (par la racine, ou par un éditeur vérifié). L'index qui les liste est lui-même signé par la racine : une copie modifiée, un hébergeur piraté, un index périmé sont refusés par l'application.

## Contrôler et publier
```
python outils/registre.py verifier
python outils/registre.py publier --cle /chemin/hors/depot/racine-principale.pem
```
`publier` contrôle tout, signe l'index (valable 60 jours : à renouveler avant), écrit `docs/` et la vitrine. La clé privée ne vit **jamais** dans ce dépôt ni dans l'intégration continue.

## Publication web
GitHub Pages sert `docs/` : Settings › Pages › Source « Deploy from a branch », branche `main`, dossier `/docs`. L'adresse de l'index est celle que Cassandra a en dur ; en changer demande une mise à jour de l'application.

Licence : AGPL-3.0 (voir `LICENSE`).
