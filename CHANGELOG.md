# Journal du registre

Chaque publication de l'index porte un **numéro de série** qui ne recule jamais (le détail signé est dans `journal.jsonl`). Ce journal dit, en clair, ce qui a changé.

## Série 3 : 30 octobre 2026
- Publiés : **billetterie 0.1.0** et **dolibarr 0.3.1**, signés par la clé racine (éditeur « Officiel »).
- Le registre dit qui le porte : La Maison Bohème.
- Répétition générale du parcours complet d'un éditeur tiers (signature, provenance, relecture, publication).

## Série 2 : 30 octobre 2026
- Republication de **sentinelle 0.1.2**.

## Série 1 : 30 octobre 2026
- Première publication : **sentinelle 0.1.2** (exemple de greffe à chaud : un moteur, un détecteur, un type d'objet, des événements).

## Sans numéro de série
- Fraîcheur : renouvelée par deux serveurs (principal et secours) en plus du poste du mainteneur ; option `--si-plus-vieille-que` pour qu'une machine de secours ne refasse rien quand la fraîcheur est récente.
- Dépôt : code de conduite, `CONTRIBUTING.md`, Dependabot, actions épinglées par empreinte de commit, `permissions: contents: read` pour la validation, surveillance quotidienne du registre publié et alerte (ticket) si la fraîcheur n'est pas renouvelée.
