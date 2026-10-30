# Registre officiel de Cassandra

**La boutique de modules de [Cassandra](https://github.com/Marplestrange), où chaque module est signé et vérifiable.**

🔎 **Voir les modules : https://marplestrange.github.io/cassandra-registre/** (recherche, filtres, une fiche par module)

🇬🇧 **English version: [README.en.md](README.en.md)**

---

## En une phrase

Cassandra est une IA qui administre vos serveurs et votre travail. Pour lui ajouter des capacités (un thème, un pont vers un logiciel, un métier), on installe des **modules**. Ce dépôt est la liste officielle de ces modules, et la preuve que chacun vient bien de qui il dit venir.

## Pourquoi ça existe

Un module **tourne dans Cassandra, avec ses droits**. Installer un module, c'est donc faire confiance à son auteur. Avant d'installer, vous devez pouvoir répondre à trois questions :

1. **Qui l'a écrit ?** Chaque module est signé : par l'équipe de Cassandra (« Officiel ») ou par un éditeur dont l'identité a été vérifiée (« Éditeur vérifié »).
2. **Est-ce bien le code d'origine ?** Une archive modifiée après sa signature est refusée. Le code d'un module d'éditeur doit en plus correspondre à son dépôt public : vous pouvez le relire tel qu'il est publié.
3. **Que demande-t-il ?** Chaque fiche liste ce que le module annonce faire (parler au réseau, lancer des processus…). Un module qui fait plus que ce qu'il annonce est refusé.

Et si un module se révèle dangereux, il est **révoqué** : toutes les installations de Cassandra le savent et refusent de l'installer.

## Installer un module

Dans Cassandra : menu de l'avatar › **Logithèque** › **Boutique**. Rien ne s'installe sans votre accord, et Cassandra vous montre ce que le module demande avant.

## Ce qui protège (sans jargon)

| Risque | Ce qui l'empêche |
|---|---|
| Un faux module qui se fait passer pour un autre | chaque archive est **signée** ; un éditeur ne publie que sous son propre nom (`<éditeur>_module`) |
| Un module modifié en route | l'**empreinte** de chaque fichier est contrôlée à l'installation |
| Un site pirate qui sert un faux catalogue | la **liste elle-même est signée** ; Cassandra connaît la clé et refuse tout le reste |
| Un vieux catalogue rejoué pour cacher un module retiré | chaque liste a un **numéro qui ne recule jamais** ; Cassandra refuse un numéro plus ancien |
| Un registre abandonné qu'on croirait encore à jour | la liste **expire**, et une preuve de fraîcheur est renouvelée chaque jour |
| Un module qui en fait plus qu'annoncé | le code est **analysé** contre ses permissions déclarées avant publication |
| Une panne de l'hébergeur | des **miroirs** peuvent servir la même liste (tout est signé, ils n'ont pas besoin d'être sûrs) |

Ce que le registre **ne garantit pas** : un module installé tourne avec les droits de Cassandra. La signature dit *qui* a publié, la relecture dit *ce que fait le code*. Le détail est dans [SECURITE.md](SECURITE.md).

## Publier un module

1. Copiez le **[modèle de module](https://github.com/Marplestrange/cassandra-module-modele)** et écrivez votre module.
2. Signez-le avec votre clé d'éditeur.
3. Ouvrez une *pull request* ici : [CONTRIBUER.md](CONTRIBUER.md) explique chaque étape.
4. Pour devenir **éditeur vérifié** : [editeurs/LISEZ-MOI.md](editeurs/LISEZ-MOI.md).

## Qui porte ce projet

Cassandra est portée par **La Maison Bohème**, association loi 1901, qui accepte les dons ([SOUTIEN.md](SOUTIEN.md)). Le code est libre (AGPL-3.0) : le meilleur soutien reste d'écrire ou de relire un module.

---

## Pour les mainteneurs

```
python outils/registre.py verifier      archives, code, éditeurs, révocations, avis, journal, index, fraîcheur ; code 1 au moindre défaut
python outils/registre.py provenance    chaque archive qui déclare sa source est reconstituée depuis elle, fichier par fichier
python outils/registre.py publier --cle racine.pem --jours 180   signe l'index (série suivante), écrit docs/ et le journal
python outils/registre.py vitrine       réécrit la vitrine depuis l'index publié (ne signe rien)
python outils/fraicheur.py renouveler --cle fraicheur.pem        signe et publie la fraîcheur (tâche planifiée, chaque jour)
```

```
cles/            les clés PUBLIQUES racine (principale et secours), les mêmes que celles embarquées dans l'application
fraicheur/       la clé PUBLIQUE de fraîcheur (jamais une racine)
editeurs/        les éditeurs vérifiés (clé publique, date d'expiration)
revocations.toml ce qui est retiré, et pourquoi (une révocation EMPÊCHE d'installer)
avis/            les avis de sécurité lisibles par une machine (un avis INFORME)
canaux.toml      la bêta et le déploiement progressif
provenance/      d'où vient le code de chaque archive d'éditeur
journal.jsonl    le journal des publications : append-only, chaîné par empreintes
docs/            ce qui est publié (GitHub Pages) : index.json, sa signature, la fraîcheur, la vitrine, les archives
outils/ tests/   l'outil de contrôle et de publication, ses bancs
```

La clé racine est **hors ligne** et ne vit jamais dans ce dépôt ni dans l'intégration continue. La clé de fraîcheur, à faible pouvoir, signe chaque jour « l'index est toujours le courant » : si elle fuit, on peut seulement prolonger la validité d'un index déjà signé. Le modèle de confiance complet est dans [GOUVERNANCE.md](GOUVERNANCE.md).

---

## English summary

**The official module registry of Cassandra**, an auto-hosted AI system administrator. Every module is a signed archive; the catalogue itself is signed, carries a never-decreasing series number (replay protection) and is kept fresh by a low-privilege key, so the offline root key stays offline.

Third-party publishers are identity-verified, namespace their modules (`<publisher>_name`), declare their source (checked by CI by rebuilding it) and pass a static analysis of their code against their declared permissions. Revocations block installation; machine-readable advisories inform; channels and staged rollout are supported.

Browse: https://marplestrange.github.io/cassandra-registre/ · Publish: [CONTRIBUER.md](CONTRIBUER.md) · Trust model: [GOUVERNANCE.md](GOUVERNANCE.md) · License: AGPL-3.0, carried by *La Maison Bohème* (French non-profit, loi 1901).
