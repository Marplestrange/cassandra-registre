## Ce que change cette proposition
<!-- Un module (nouvelle version ?), un éditeur, une révocation, un avis, la documentation… -->

## Pour un module
- [ ] L'archive est signée par ma clé d'éditeur (`python CN_main.py paquet construire … --cle editeur.pem`).
- [ ] Le nom est préfixé par mon identifiant d'éditeur (`<éditeur>_nom`).
- [ ] `provenance/<id>-<version>.toml` indique mon dépôt public et le commit publié.
- [ ] `[permissions]` annonce ce que le module fait (réseau, processus…).
- [ ] J'ai lancé `python outils/registre.py verifier` et `python outils/registre.py provenance` : tout est vert.
- [ ] Un `CN_CHANGELOG.md` dit ce qui change.

## Pour une clé d'éditeur
- [ ] Je n'ai mis que la clé **publique**.
- [ ] J'ai proposé une date d'expiration.
