# Sécurité

## Ce que le registre garantit
- Une archive affichée « Officiel » ou « Éditeur vérifié » est **signée** et n'a pas été modifiée depuis (SOMMES + signature Ed25519).
- L'index est **signé** : un hébergeur compromis ne peut pas y glisser une archive ou une empreinte truquée.
- Un index **périmé** ou daté du futur est refusé ; un module **révoqué** n'est pas installé.

## Ce qu'il ne garantit PAS
- **Un module installé tourne dans Cassandra, avec ses droits.** Ses permissions (réseau, écritures, privilèges) sont déclaratives : le cloisonnement par processus n'existe pas encore. La signature dit **qui** a publié, pas que le code est inoffensif ; la relecture et la révocation sont la protection.
- Pas de modules payants ni de clés de licence.

## Signaler une faille
Écris à marplestrange@cassandra.center (ou ouvre un signalement privé sur le dépôt). Ne publie pas la faille avant qu'elle soit corrigée. Un module dangereux est révoqué sans attendre, avec sa raison.
