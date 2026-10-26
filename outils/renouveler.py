"""Renouvelle l'index du registre quand il approche de son expiration, puis le pousse.

À lancer par une tâche planifiée sur la machine qui garde la clé racine (la clé ne quitte jamais cette machine).
  python outils/renouveler.py --cle C:/chemin/racine-principale.pem [--seuil 30] [--forcer]
Ne fait rien tant qu'il reste plus de `seuil` jours de validité. Code de sortie 0 = rien à faire ou renouvelé et poussé ; 1 = échec (à voir dans le journal).
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def git(*args):
    r = subprocess.run(["git", *args], cwd=RACINE, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit("git %s : %s" % (" ".join(args), (r.stderr or r.stdout).strip()))
    return r.stdout.strip()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cle", required=True)
    p.add_argument("--seuil", type=int, default=30, help="renouveler s'il reste moins de N jours")
    p.add_argument("--jours", type=int, default=60)
    p.add_argument("--forcer", action="store_true")
    a = p.parse_args(argv)
    git("pull", "--ff-only")
    restant = (json.loads((RACINE / "docs" / "index.json").read_text(encoding="utf-8"))["expire"] - time.time()) / 86400
    print("validité restante : %.1f jours" % restant)
    if restant > a.seuil and not a.forcer:
        print("rien à faire")
        return 0
    r = subprocess.run([sys.executable, str(RACINE / "outils" / "registre.py"), "publier", "--cle", a.cle, "--jours", str(a.jours)], cwd=RACINE)
    if r.returncode:
        return 1
    git("add", "docs")
    git("commit", "-m", "Renouvellement automatique de l'index (%d jours)" % a.jours)
    git("push")
    print("renouvelé et poussé")
    return 0


if __name__ == "__main__":
    sys.exit(main())
