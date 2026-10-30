# Registre officiel de Cassandra

*English summary below.*

Le magasin de modules de [Cassandra](https://github.com/Marplestrange) : ce dépôt est la **source de vérité**. Ce qu'il contient, signé, est ce que la Logithèque de Cassandra propose.
La vitrine publique (recherche, filtres, une fiche par module avec ses permissions et son empreinte) est servie par GitHub Pages depuis `docs/`.

- **Installer un module** : dans Cassandra, menu avatar › Logithèque › Boutique.
- **Publier un module** : [CONTRIBUER.md](CONTRIBUER.md). Devenir éditeur vérifié : [editeurs/LISEZ-MOI.md](editeurs/LISEZ-MOI.md). Modèle de module prêt à copier : `cassandra-module-modele`.
- **Comprendre la confiance** : [GOUVERNANCE.md](GOUVERNANCE.md) et [SECURITE.md](SECURITE.md).
- **Soutenir le projet** : [SOUTIEN.md](SOUTIEN.md).

## Comment ça tient
```
cles/               les clés PUBLIQUES racine (principale et secours) : la racine de confiance, la même que celle embarquée dans l'application
fraicheur/          la clé PUBLIQUE de fraîcheur : elle atteste chaque jour que l'index est toujours le courant (jamais une racine)
editeurs/           les éditeurs dont l'identité est vérifiée (leur clé publique, sa date d'expiration)
revocations.toml    ce qui est retiré, et pourquoi (une révocation EMPÊCHE d'installer)
avis/               les avis de sécurité, lisibles par une machine (un avis INFORME : gravité, versions touchées, correctif)
canaux.toml         la bêta et le déploiement progressif (quelle version, à quel pourcentage des installations)
provenance/         d'où vient le code de chaque archive d'éditeur (dépôt public et commit) : on peut le relire tel qu'il est publié
journal.jsonl       le journal des publications : append-only, chaîné par empreintes
docs/               ce qui est PUBLIÉ (servi tel quel) : index.json, index.json.sig, fraicheur.json, la vitrine, modules/<id>/<id>-<version>.cmod
outils/registre.py     contrôle le dépôt et publie l'index signé (hors ligne, avec la clé racine)
outils/fraicheur.py    la clé de fraîcheur : signer chaque jour que l'index est à jour
tests/              les bancs de l'outil
```

Un module est une archive `.cmod` **signée** (par la racine, ou par un éditeur vérifié). L'index qui les liste est lui-même signé par la racine : une copie modifiée, un
hébergeur piraté, un index rejoué plus tard (la **série** ne revient jamais en arrière) ou un module révoqué qu'on voudrait cacher sont refusés par l'application.

## Contrôler et publier
```
python outils/registre.py verifier                         archives, analyse du code, éditeurs, révocations, avis, journal, index, fraîcheur ; code 1 au moindre défaut
python outils/registre.py provenance                       chaque archive qui déclare sa source est reconstituée depuis elle, fichier par fichier
python outils/registre.py publier --cle /chemin/hors/depot/racine-principale.pem
python outils/registre.py vitrine                          réécrit la vitrine depuis l'index déjà publié (ne signe rien)
```
`publier` contrôle tout, signe l'index (série suivante), écrit `docs/` (l'index, la vitrine, une page par module) et ajoute une ligne au journal.
La clé racine ne vit **jamais** dans ce dépôt ni dans l'intégration continue.

## Garder l'index frais sans ressortir la racine
L'index a une date d'expiration : un registre qu'on ne tient plus à jour cesse d'être cru. Pour ne pas ressortir la clé racine toutes les quelques semaines, une seconde clé,
à faible pouvoir, signe chaque jour `docs/fraicheur.json` (« l'index n° N est toujours le courant »). Si elle fuit, on peut seulement prolonger la fraîcheur d'un index
déjà signé par la racine. Mise en place : `python outils/fraicheur.py init DOSSIER`, republier l'index avec la racine, puis mettre la clé privée dans le secret
`FRAICHEUR_CLE_PRIVEE` et la variable `FRAICHEUR_ACTIVE=oui` du dépôt : `.github/workflows/fraicheur.yml` s'en charge.

## Publication web
GitHub Pages sert `docs/` : Settings › Pages › Source « Deploy from a branch », branche `main`, dossier `/docs`. L'application connaît l'adresse de l'index et, en secours, celles de ses
miroirs : en changer demande une mise à jour de l'application. Un miroir est une copie byte-à-byte de `docs/` sur un autre hébergeur : il n'a pas besoin d'être de confiance, puisque tout est signé.

Licence : AGPL-3.0 (voir `LICENSE`). Le projet est porté par **La Maison Bohème**, association loi 1901.

---

## English summary

The official module registry of **Cassandra**, an auto-hosted AI system administrator. This repository is the source of truth for what Cassandra's module store (the *Logithèque*) offers.

- Modules ship as signed `.cmod` archives (Ed25519). The **index is signed** by an offline root key; a **freshness key** with low privilege re-attests daily that the index is current, so the root key never has to come out just to renew it.
- The index carries a monotonically increasing **series number**: a replayed older index is refused. Every publication is appended to a hash-chained, append-only **journal**.
- Third-party publishers must be **verified**, namespace their modules (`<publisher>_name`), declare their **provenance** (public repository + commit, checked by CI by rebuilding), and pass a static **analysis** of their code against their declared permissions.
- **Revocations** block installation; machine-readable **security advisories** inform; **channels** (stable/beta) and **staged rollout** (`pourcent`) are supported.
- See [CONTRIBUER.md](CONTRIBUER.md) to publish, [GOUVERNANCE.md](GOUVERNANCE.md) for the trust model, [SECURITE.md](SECURITE.md) for what is and is not guaranteed.

License: AGPL-3.0. The project is carried by *La Maison Bohème*, a French non-profit association (loi 1901).
