#!/usr/bin/env python3
"""Fabrique l'archive signée d'un module livré avec Cassandra, pour le registre.

    python outils/construire_officiel.py --cassandra C:/chemin/Cassandra-V19 --module billetterie --cle racine-principale.pem

Un module livré avec le noyau porte `confiance = "interne"`, que le registre refuse (elle est réservée à ce qui vient avec le noyau). On construit donc l'archive à partir d'une COPIE
dont seule cette ligne change (`confiance = "signe"` : signé par la racine) ; rien d'autre n'est modifié, ni le code ni les fichiers (sans `__pycache__`). L'archive est écrite dans
docs/modules/<id>/<id>-<version>.cmod, au format et par l'outil de Cassandra (`CN_main.py paquet construire`), puis relue par `registre.py verifier`.
La clé privée est celle de la racine : elle reste hors de ce dépôt.
"""
import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cassandra", required=True, help="le dépôt de Cassandra (qui contient CN_main.py et modules/)")
    p.add_argument("--module", required=True)
    p.add_argument("--cle", required=True, help="la clé privée racine (PEM Ed25519), hors de ce dépôt")
    a = p.parse_args(argv)
    src = Path(a.cassandra) / "modules" / a.module
    if not (src / "CN_manifeste.toml").is_file():
        print("pas de module %s dans %s" % (a.module, a.cassandra), file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as t:
        copie = Path(t) / a.module
        shutil.copytree(src, copie, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
        f = copie / "CN_manifeste.toml"
        texte = f.read_text(encoding="utf-8")
        nouveau, n = re.subn(r'(?m)^confiance\s*=\s*"interne"', 'confiance = "signe"', texte, count=1)
        if n != 1:
            print("le manifeste ne porte pas confiance = \"interne\" : rien à convertir", file=sys.stderr)
            return 1
        f.write_text(nouveau, encoding="utf-8", newline="")
        version = str(tomllib.loads(nouveau)["module"]["version"])
        sortie = RACINE / "docs" / "modules" / a.module / ("%s-%s.cmod" % (a.module, version))
        sortie.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([sys.executable, str(Path(a.cassandra) / "CN_main.py"), "paquet", "construire", str(copie), "--cle", a.cle, "--sortie", str(sortie)], capture_output=True, text=True)
        if r.returncode:
            print((r.stderr or r.stdout).strip(), file=sys.stderr)
            return 1
    print("archive écrite : %s" % sortie.relative_to(RACINE).as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main())
