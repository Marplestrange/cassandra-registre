# Publier un module

1. **Écris ton module** avec l'assistant de Cassandra : `python CN_main.py module nouveau mon_module`. Le manifeste doit déclarer `importance` (`vital`, `important`, `optionnel`) et `sans` (ce qui s'arrête sans lui) ; l'identifiant, la version et le nom de fichier doivent concorder.
2. **Signe-le** avec ta clé d'éditeur (voir [editeurs/LISEZ-MOI.md](editeurs/LISEZ-MOI.md)) : `python CN_main.py paquet construire mon_module --cle editeur.pem` fabrique `mon_module-1.0.0.cmod`.
3. **Propose-le** par *pull request* : ajoute l'archive en `docs/modules/<id>/<id>-<version>.cmod`. L'intégration continue contrôle : nom, SOMMES, signature (racine ou éditeur vérifié), manifeste, taille.
4. **Relecture** : l'équipe lit le code (un module tourne DANS Cassandra avec ses droits ; ses permissions ne sont pas encore cloisonnées : c'est la relecture qui protège). Elle publie ensuite l'index signé.

## Ce qui est refusé d'office
- une archive non signée, ou signée par une clé inconnue ;
- une archive modifiée après sa signature (SOMMES) ;
- `confiance = "interne"` (réservée aux modules livrés avec Cassandra) ;
- une archive qui sort de son dossier, contient un lien ou dépasse 32 Mo.

## Mettre à jour, retirer
- Nouvelle version : une nouvelle archive (`-1.1.0.cmod`) ; l'ancienne reste téléchargeable mais n'est plus listée.
- Module dangereux : une entrée dans `revocations.toml`, **avec sa raison**.
