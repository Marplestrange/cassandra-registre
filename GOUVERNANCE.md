# Gouvernance et racine de confiance

## Qui décide
L'équipe de Cassandra décide de ce qui est publié. Elle seule détient les clés racine.

## La racine
Deux clés publiques Ed25519 sont embarquées dans l'application (`noyau/CN_registre_officiel.py`) et reprises dans `cles/` :
- **racine-principale** : signe l'index et les modules officiels.
- **racine-secours** : une seconde clé, déjà embarquée, gardée à part, hors ligne. Elle sert si la principale est perdue ou compromise.

Les clés privées sont **hors ligne** (sur une machine de l'équipe, sauvegardées chiffrées en deux endroits), jamais dans ce dépôt, jamais dans l'intégration continue.

## Les trois niveaux
- **Officiel** : signé par une clé racine (écrit ou relu par l'équipe).
- **Éditeur vérifié** : signé par un éditeur de `editeurs/` dont l'identité a été vérifiée.
- **Local** : signé par une clé que l'administrateur d'une instance a posée lui-même (hors registre).

## Rotation ou compromission
1. Perte ou fuite de la clé principale : la **secours** signe un index qui le dit ; une mise à jour de l'application embarque la nouvelle racine ; l'ancienne est retirée.
2. Un éditeur compromis : sa clé quitte `editeurs/`, ses modules entrent dans `revocations.toml` avec la raison.
3. L'index expire (60 jours) : un registre qu'on ne tient plus à jour cesse d'être cru. Le renouveler est une tâche récurrente.

## Transparence
Chaque publication est un commit relu et daté : l'historique du dépôt est le journal d'audit.
