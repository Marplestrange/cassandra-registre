# Sécurité

## Ce que le registre garantit
- Une archive affichée « Officiel » ou « Éditeur vérifié » est **signée** et n'a pas été modifiée depuis (SOMMES + signature Ed25519).
- L'index est **signé** : un hébergeur compromis ne peut pas y glisser une archive ou une empreinte truquée.
- Un index **périmé**, daté du futur, **plus ancien** que le dernier vu (série) ou **sans fraîcheur** quand il en annonce une est refusé ; un module **révoqué** n'est pas installé.
- Le code d'un module d'éditeur est **celui de son dépôt public** au commit déclaré (la provenance est reconstituée par l'intégration continue) : il se relit tel qu'il est publié.
- Un module de tiers qui sort de ce que son manifeste annonce (réseau, processus, `ctypes`, code masqué) n'entre pas.
- Chaque publication est inscrite dans un journal chaîné : on ne peut pas retirer une ligne sans que cela se voie.

## Ce qu'il ne garantit PAS
- **Un module installé tourne dans Cassandra, avec ses droits.** Ses permissions (réseau, écritures, privilèges) sont déclaratives : le cloisonnement par processus n'existe pas encore. La signature dit **qui** a publié, la provenance dit **d'où vient le code**, l'analyse attrape les écarts grossiers ; **seule la relecture** décide si le code est sain. L'analyse statique n'est pas une preuve d'innocuité.
- La clé de fraîcheur est une clé en ligne : si elle fuit, on peut prolonger la validité d'un index **déjà signé**, rien de plus.
- Pas de modules payants ni de clés de licence.
- Pas de statistiques d'installation : aucune télémétrie n'est demandée à votre machine.

## Les avis et les révocations
- Une **révocation** (`revocations.toml`) EMPÊCHE d'installer ; chaque installation la lit dans l'index signé et signale ce qui est déjà installé. La raison est obligatoire et publique.
- Un **avis** (`avis/<id>.toml`) INFORME : module, gravité (faible, moyenne, haute, critique), versions touchées, version qui corrige, référence CVE. Il s'affiche sur la fiche du module.

## Signaler une faille
Écris à marplestrange@cassandra.center (ou ouvre un signalement privé sur le dépôt). Ne publie pas la faille avant qu'elle soit corrigée. Un module dangereux est révoqué sans attendre, avec sa raison, et un avis est publié.
