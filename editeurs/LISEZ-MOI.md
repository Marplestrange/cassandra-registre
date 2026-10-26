# Les éditeurs

Un éditeur est une personne ou une organisation dont l'équipe de Cassandra a **vérifié l'identité** et dont elle publie la **clé publique** ici. Une archive signée par sa clé est affichée « Éditeur vérifié » dans l'App Store de Cassandra ; sans cette vérification, elle est « non signée » et refusée par la politique par défaut.

## Devenir éditeur
1. Génère ta paire de clés (la privée ne quitte jamais ta machine) :
   ```
   openssl genpkey -algorithm ed25519 -out editeur.pem
   openssl pkey -in editeur.pem -pubout -out editeur.pub
   ```
2. Copie `editeur.toml.modele` en `editeurs/<ton_id>.toml` (minuscules, chiffres, `_`), mets ta clé **publique** et ouvre une *pull request*.
3. L'équipe vérifie ton identité (hors dépôt) puis passe `verifie = true`. Tant que ce n'est pas fait, ta clé n'est pas publiée.

## Règles
- Une clé compromise se signale tout de suite : elle est retirée et ses modules sont révoqués (`revocations.toml`).
- Un éditeur ne signe que ses propres modules.
