#!/usr/bin/env python3
"""La clé de fraîcheur : prouver chaque jour que l'index publié est TOUJOURS le bon, sans ressortir la clé racine.

Le problème : l'index expire (pour qu'un registre abandonné cesse d'être cru), donc il fallait ressortir la clé racine, hors ligne, toutes les quelques semaines.
La solution (le rôle « timestamp » de TUF) : la racine signe, UNE FOIS, l'index, et y inscrit la clé publique de fraîcheur. Une seconde clé, à faible pouvoir, signe
chaque jour `docs/fraicheur.json` : « l'index n° N (empreinte X) est toujours le courant, jusqu'à telle date ». Elle peut vivre dans l'intégration continue : si elle fuit,
un voleur peut seulement RENOUVELER la fraîcheur d'un index que la racine a déjà signé, jamais publier ni retirer un module, ni masquer une révocation déjà publiée.

    python outils/fraicheur.py init DOSSIER                  fabrique la paire de clés : la publique va dans fraicheur/fraicheur.pub (à commiter), la privée reste dans DOSSIER
    python outils/fraicheur.py signer --cle fraicheur.pem    écrit docs/fraicheur.json et docs/fraicheur.json.sig (valables 7 jours)
    python outils/fraicheur.py verifier                      contrôle ce qui est publié

Ensuite : republier l'index avec la clé racine (`registre.py publier`) pour qu'il annonce la clé de fraîcheur, puis mettre la clé privée dans le secret
FRAICHEUR_CLE_PRIVEE du dépôt GitHub : le travail `.github/workflows/fraicheur.yml` renouvelle la fraîcheur tous les jours.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("registre", RACINE / "outils" / "registre.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


def cmd_init(a):
    d = Path(a.dossier)
    d.mkdir(parents=True, exist_ok=True)
    priv = d / "fraicheur.pem"
    if priv.exists():
        raise R.Defaut("%s existe déjà : on ne l'écrase pas" % priv)
    R.openssl("genpkey", "-algorithm", "ed25519", "-out", str(priv))
    pub = R.openssl("pkey", "-in", str(priv), "-pubout").stdout.decode().replace("\r", "")
    cible = R.RACINE / R.CHEMIN_FRAICHEUR
    cible.mkdir(exist_ok=True)
    (cible / "fraicheur.pub").write_text(pub, encoding="utf-8")
    print("clé privée : %s (à garder, jamais dans le dépôt ; à mettre dans le secret GitHub FRAICHEUR_CLE_PRIVEE)\nclé publique : %s (à commiter)" % (priv, cible / "fraicheur.pub"))
    print("Étape suivante : republier l'index avec la clé racine pour qu'il annonce cette clé de fraîcheur.")


def cmd_signer(a):
    f = R.RACINE / "docs" / "index.json"
    if not f.is_file():
        raise R.Defaut("pas d'index publié")
    brut = json.loads(f.read_text(encoding="utf-8"))
    fr = brut.get("fraicheur")
    if not fr:
        raise R.Defaut("l'index publié n'annonce pas de clé de fraîcheur : republiez-le d'abord avec la clé racine (fraicheur/fraicheur.pub doit exister)")
    cle = Path(a.cle)
    if not cle.is_file():
        raise R.Defaut("clé introuvable : %s" % cle)
    pub = R.openssl("pkey", "-in", str(cle), "-pubout").stdout.decode().replace("\r", "").strip()
    if pub != fr["cle"].replace("\r", "").strip():
        raise R.Defaut("cette clé n'est pas celle que l'index annonce : la fraîcheur serait refusée")
    now = int(time.time())
    d = {"serie": brut["serie"], "index_sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "emis": now, "expire": now + int(fr.get("validite_s", R.VALIDITE_FRAICHEUR_S))}
    octets = (json.dumps(d, sort_keys=True, indent=1) + "\n").encode("utf-8")
    (R.RACINE / "docs" / "fraicheur.json").write_bytes(octets)
    (R.RACINE / "docs" / "fraicheur.json.sig").write_bytes(R.signer(octets, cle))
    R.verifier_fraicheur_publiee()
    print("fraîcheur signée pour l'index n° %d, valable jusqu'au %s" % (d["serie"], time.strftime("%d/%m/%Y %H:%M", time.gmtime(d["expire"]))))


def cmd_verifier(_):
    R.verifier_fraicheur_publiee()
    print("OK")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    i = sp.add_parser("init")
    i.add_argument("dossier")
    i.set_defaults(f=cmd_init)
    s = sp.add_parser("signer")
    s.add_argument("--cle", required=True)
    s.set_defaults(f=cmd_signer)
    sp.add_parser("verifier").set_defaults(f=cmd_verifier)
    a = p.parse_args(argv)
    try:
        a.f(a)
    except R.Defaut as ex:
        print("REFUSÉ : %s" % ex, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
