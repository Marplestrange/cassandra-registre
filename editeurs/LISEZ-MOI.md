# Les éditeurs

Un éditeur est une personne ou une organisation dont l'équipe de Cassandra a **vérifié l'identité** et dont elle publie la **clé publique** ici. Une archive signée par sa clé est affichée « Éditeur vérifié » dans la Logithèque de Cassandra ; sans cette vérification, elle est « non signée » et refusée par la politique par défaut.

## Devenir éditeur
1. Génère ta paire de clés (la privée ne quitte jamais ta machine) :
   ```
   openssl genpkey -algorithm ed25519 -out editeur.pem
   openssl pkey -in editeur.pem -pubout -out editeur.pub
   ```
2. Copie `editeur.toml.modele` en `editeurs/<ton_id>.toml` (minuscules, chiffres, `_`), mets ta clé **publique** et ouvre une *pull request*. Ton identifiant devient le préfixe de tous tes modules (`<ton_id>_nom`).
3. L'équipe vérifie ton identité (hors dépôt : pièce d'identité ou extrait d'immatriculation, échange par un canal que tu ne contrôles pas dans ce dépôt) puis passe `verifie = true` et fixe `expire`. Tant que ce n'est pas fait, ta clé n'est pas publiée.

## La vie d'une clé
- **Elle expire** (au plus tous les deux ans) : à la date `expire`, elle n'est plus publiée et tes archives sont refusées. Pour renouveler, génère une nouvelle paire, remplace `cle`, change `expire`, et resigne tes modules.
- **Rotation** : si tu changes de clé en cours de route, l'ancienne reste valide jusqu'à son `expire` ; dis-le dans la *pull request*.
- **Compromission** : signale-le tout de suite (marplestrange@cassandra.center). Ta clé quitte `editeurs/`, tes modules entrent dans `revocations.toml` avec la raison, un avis est publié dans `avis/`.

## Règles
- Un éditeur ne signe que ses propres modules, tous préfixés par son identifiant.
- Chaque archive publiée dit d'où vient son code (`provenance/`) : un dépôt public, un commit.
- Un module qui fait ce que son manifeste n'annonce pas (réseau, processus…) est refusé, et un éditeur qui y revient perd sa vérification.
