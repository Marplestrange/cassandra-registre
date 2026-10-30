# Gouvernance et racine de confiance

## Qui décide
L'équipe de Cassandra décide de ce qui est publié. Elle seule détient les clés racine. Le projet est porté par La Maison Bohème, association loi 1901 (voir [SOUTIEN.md](SOUTIEN.md)).

## Les trois clés, trois pouvoirs
| Clé | Où vit-elle | Ce qu'elle peut | Si elle fuit |
|---|---|---|---|
| **racine-principale** | hors ligne, sauvegardée chiffrée en deux endroits | signer l'index et les modules officiels | la **secours** signe un index qui l'annonce ; une mise à jour de l'application embarque la nouvelle racine |
| **racine-secours** | hors ligne, gardée à part, déjà embarquée dans l'application | remplacer la principale | idem, en sens inverse |
| **fraîcheur** | sur deux serveurs du mainteneur (principal et secours) et sur son poste, jamais dans un dépôt | signer chaque jour « l'index n° N est toujours le courant » | on peut prolonger la fraîcheur d'un index déjà signé : **jamais** publier, retirer ou masquer quoi que ce soit ; on la remplace en republiant l'index avec une nouvelle clé de fraîcheur |

Les deux clés racine sont embarquées dans l'application (`noyau/CN_registre_officiel.py`) et reprises dans `cles/`. La clé de fraîcheur est publiée dans `fraicheur/` **et inscrite dans l'index signé par la racine** : l'application ne croit une clé de fraîcheur que parce que la racine l'a nommée.

## Les trois niveaux
- **Officiel** : signé par une clé racine (écrit ou relu par l'équipe).
- **Éditeur vérifié** : signé par un éditeur de `editeurs/` dont l'identité a été vérifiée. Sa clé a une durée de vie (`expire`) ; passé la date, elle n'est plus publiée et ses archives sont refusées jusqu'au renouvellement.
- **Local** : signé par une clé que l'administrateur d'une instance a posée lui-même (hors registre).

## Les garde-fous du registre
- **Série croissante** : chaque index publié porte un numéro qui ne revient jamais en arrière. L'application mémorise le plus haut vu et refuse un index plus ancien : un miroir malveillant ne peut pas rejouer un vieil index (valide, mais d'avant une révocation) pour la cacher.
- **Journal** (`journal.jsonl`) : une ligne par publication, chaînée par empreintes à la précédente. En retirer ou en modifier une casse la chaîne ; l'intégration continue le contrôle, et l'historique git est le second témoin.
- **Espace de noms** : un module d'éditeur s'appelle `<éditeur>_nom`. Nul ne peut prendre le nom d'un autre.
- **Provenance** : un module d'éditeur dit d'où vient son code ; l'intégration continue le reconstitue depuis ce dépôt au commit déclaré et exige l'identité fichier par fichier.
- **Analyse du code** : un module de tiers qui parle au réseau, lance des processus, utilise `ctypes` ou masque son code sans l'avoir déclaré est refusé. Pour un module officiel, tout reste une alerte affichée sur sa fiche.
- **Canaux et déploiement progressif** : une version peut être en bêta, ou proposée à une part seulement des installations, avant d'être offerte à tous.

## Rotation ou compromission
La procédure détaillée, étape par étape, est dans [ROTATION.md](ROTATION.md) : l'application ne croit une nouvelle clé principale que si elle est annoncée par la clé de **secours**, et il faut ensuite resigner les modules officiels.

1. Perte ou fuite de la clé principale : la **secours** signe un index qui le dit ; une mise à jour de l'application embarque la nouvelle racine ; l'ancienne est retirée.
2. Fuite de la clé de fraîcheur : en générer une autre (`outils/fraicheur.py init`), republier l'index avec la racine, remplacer la clé sur chaque machine de renouvellement (et révoquer leurs clés de dépôt dans *Settings › Deploy keys*).
3. Un éditeur compromis : sa clé quitte `editeurs/`, ses modules entrent dans `revocations.toml` avec la raison, un avis est publié dans `avis/`.
4. L'index expire : avec la clé de fraîcheur, c'est automatique ; sans elle, le renouveler est une tâche récurrente (`outils/renouveler.py`).

## Qui renouvelle la fraîcheur

| Machine | Rôle | Quand | Renouvelle si la fraîcheur a plus de |
|---|---|---|---|
| serveur principal | principal | deux fois par jour (cron) | 10 h |
| serveur de secours | secours | toutes les 6 h (conteneur) | 20 h |
| poste du mainteneur | dernier recours | tâche planifiée quotidienne | toujours |

Chaque machine a sa propre clé de dépôt, limitée à ce dépôt. La commande est `python outils/fraicheur.py renouveler --cle CLE --si-plus-vieille-que HEURES`. Une surveillance GitHub (`surveillance.yml`) vérifie chaque jour le registre publié et ouvre un ticket si la fraîcheur a plus de 36 h. Le job `fraicheur.yml` reste disponible (variable `FRAICHEUR_ACTIVE`), désactivé tant qu'aucun secret GitHub ne porte la clé.

## Miroirs
Une copie de `docs/` sur un autre hébergeur sert de secours si le premier tombe. Elle n'a pas besoin d'être de confiance : tout ce qu'elle sert est signé, et la série empêche qu'elle serve un index ancien. Les adresses des miroirs sont connues de l'application, comme l'adresse principale.

## Transparence
Chaque publication est un commit relu et daté, et une ligne du journal : l'historique du dépôt est le journal d'audit.
