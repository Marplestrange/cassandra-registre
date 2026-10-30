# Publier un module

Le plus court : copie le dépôt modèle `cassandra-module-modele` (manifeste, module, tests et intégration continue prêts), renomme-le, écris ton module.

1. **Écris ton module** avec l'assistant de Cassandra : `python CN_main.py module nouveau acme_mon_module`. Le manifeste doit déclarer `importance` (`vital`, `important`, `optionnel`) et `sans` (ce qui s'arrête sans lui) ; l'identifiant, la version et le nom de fichier doivent concorder. **Un module d'éditeur porte le nom de son éditeur** : `<éditeur>_nom` (les modules officiels n'ont pas ce préfixe).
2. **Déclare ce qu'il fait.** `[permissions]` : `reseau = ["à quoi il parle"]` si le module ouvre une connexion, `racine` ou `privileges` s'il lance des processus. Le code est analysé : un module qui fait ce qu'il n'a pas déclaré est refusé. Mets un `CN_CHANGELOG.md` dans le module : il s'affiche sur sa fiche.
3. **Signe-le** avec ta clé d'éditeur (voir [editeurs/LISEZ-MOI.md](editeurs/LISEZ-MOI.md)) : `python CN_main.py paquet construire acme_mon_module --cle editeur.pem` fabrique `acme_mon_module-1.0.0.cmod`.
4. **Dis d'où vient le code** : `provenance/<id>-<version>.toml`, avec le dépôt public (`https`), le commit (40 caractères) et, si le module n'est pas à la racine du dépôt, son `dossier`. L'intégration continue récupère ce commit et exige que chaque fichier de l'archive soit identique à celui du dépôt.
   ```toml
   depot = "https://github.com/acme/mon-module"
   commit = "0123456789abcdef0123456789abcdef01234567"
   dossier = "acme_mon_module"
   ```
5. **Propose-le** par *pull request* : ajoute l'archive en `docs/modules/<id>/<id>-<version>.cmod` et sa provenance. L'intégration continue contrôle : nom, SOMMES, signature (racine ou éditeur vérifié), manifeste, taille, analyse du code, provenance.
6. **Relecture** : l'équipe lit le code (un module tourne DANS Cassandra avec ses droits ; ses permissions ne sont pas encore cloisonnées : c'est la relecture qui protège). Elle publie ensuite l'index signé.

## Ce qui est refusé d'office
- une archive non signée, ou signée par une clé inconnue ou expirée ;
- une archive modifiée après sa signature (SOMMES), ou qui n'est pas la copie exacte de la source déclarée ;
- `confiance = "interne"` (réservée aux modules livrés avec Cassandra) ;
- un nom qui n'est pas préfixé par l'éditeur, ou un module d'éditeur sans provenance ;
- du réseau, des processus, `ctypes` ou du code masqué que le manifeste n'annonce pas ;
- une archive qui sort de son dossier, contient un lien ou dépasse 32 Mo.

## Mettre à jour, retirer
- **Nouvelle version** : une nouvelle archive (`-1.1.0.cmod`) ; l'ancienne reste téléchargeable mais n'est plus offerte.
- **Bêta ou déploiement progressif** : `canaux.toml`.
  ```toml
  [[publication]]
  id = "acme_mon_module"
  version = "1.1.0"
  canal = "stable"
  pourcent = 25          # offerte à 25 % des installations ; les autres gardent la version précédente
  [[publication]]
  id = "acme_mon_module"
  version = "1.2.0"
  canal = "beta"         # visible seulement de ceux qui choisissent la bêta
  ```
- **Module dangereux** : une entrée dans `revocations.toml`, **avec sa raison** (cela empêche l'installation) ; et un avis dans `avis/` pour dire la gravité, les versions touchées et le correctif.
  ```toml
  id = "AV-2026-001"
  module = "acme_mon_module"
  gravite = "haute"                  # faible, moyenne, haute, critique
  resume = "Lit des fichiers hors de son espace."
  versions_touchees = "<1.1"
  corrige_en = "1.1.0"
  cve = ""                           # si vous en avez un
  ```
