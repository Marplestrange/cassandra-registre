# Remplacer la clé principale (rotation)

La clé **principale** signe l'index et les modules officiels. Si elle est perdue, volée ou simplement vieille, la clé de **secours**, gardée hors ligne à part, annonce une nouvelle principale. Les installations de Cassandra y croient **à une seule condition : que l'annonce soit signée par la secours**.
Une principale volée ne peut donc pas s'offrir un remplaçant, ni retirer la secours.

## Ce que fait l'application

Quand elle reçoit un index signé par la **secours** qui porte `rotation = {nom: "principale", retire: ["principale"], cle: …}`, elle garde la nouvelle clé (elle survit au redémarrage) et **l'ancienne principale ne vaut plus rien**. Une annonce signée par une autre clé est ignorée ; une annonce de la secours qui veut retirer autre chose que la principale est refusée.

## La procédure

1. **Fabriquer la nouvelle paire** (hors ligne, de préférence sur une machine sans réseau) :
   ```
   openssl genpkey -algorithm ed25519 -out racine-principale-NOUVELLE.pem
   openssl pkey -in racine-principale-NOUVELLE.pem -pubout -out racine-principale-NOUVELLE.pub
   ```
2. **Annoncer** : créer `rotation.toml` à la racine du dépôt (la raison est obligatoire, elle est publique) :
   ```toml
   nouvelle_cle = """-----BEGIN PUBLIC KEY-----
   …le contenu de racine-principale-NOUVELLE.pub…
   -----END PUBLIC KEY-----
   """
   raison = "Remplacement préventif de la clé principale"
   ```
3. **Publier avec la clé de SECOURS** (l'outil refuse toute autre clé tant que `rotation.toml` existe) :
   ```
   python outils/registre.py publier --cle racine-secours.pem
   ```
   Chaque installation qui relit l'index adopte la nouvelle principale. Laisser **au moins quelques semaines** (le temps que toutes les installations aient relu l'index) avant l'étape suivante.
4. **Resigner les modules officiels** avec la nouvelle clé : leurs archives étaient signées par l'ancienne principale, qui n'est plus une racine.
   ```
   python outils/construire_officiel.py --cassandra CHEMIN --module billetterie --cle racine-principale-NOUVELLE.pem
   ```
   (pour chaque module officiel).
5. **Remplacer** `cles/racine-principale.pub` par la nouvelle clé publique, supprimer `rotation.toml`, puis republier avec la **nouvelle** principale : `python outils/registre.py publier --cle racine-principale-NOUVELLE.pem`.
6. **Mettre à jour l'application** : la nouvelle clé est embarquée dans `noyau/CN_registre_officiel.py` (`CLES_RACINE["principale"]`) à la prochaine version, et son empreinte est mise à jour dans le [README](README.md) et dans `outils/verifier_independant.py`.
7. **Ranger l'ancienne clé** : elle est détruite (sauf sauvegarde chiffrée si une enquête le demande).

## Perte de la secours
La secours ne sert qu'à cela. Si c'est elle qu'on perd, la principale suffit encore à tout signer : on fabrique une nouvelle secours et on la publie par une **mise à jour de l'application** (une clé racine ne se remplace pas par le registre seul). Ne jamais ranger les deux clés au même endroit.

## Le test à blanc
Le banc `tests/test_registre_v3.py` joue toute la chaîne avec des clés d'essai : annonce par la secours, refus par la principale, resignature, republication. Côté application, `tests/CN_test_registre_serie.py` (dépôt de Cassandra) joue l'adoption de la nouvelle clé, son maintien après redémarrage, le refus de l'ancienne et l'ignorance d'une annonce faite par une autre clé.
