#!/usr/bin/env python3
"""La répétition générale : joue, dans un dossier jetable et avec des clés jetables, le parcours COMPLET d'un éditeur tiers contre le VRAI GitHub.

    python outils/repetition_generale.py --cassandra C:/chemin/Cassandra-V19

Ce qui est joué : un éditeur vérifié (clé jetable) construit un module à partir du dépôt modèle public (`cassandra-module-modele`), le signe, déclare sa provenance ;
le registre contrôle l'archive, RECONSTITUE le code depuis GitHub au commit déclaré, publie un index signé ; puis une révocation et un avis sont publiés, et le vérificateur indépendant
confirme que tout est authentique (et refuse une copie modifiée). Rien n'est écrit dans le vrai registre, aucune vraie clé n'est utilisée.
"""
import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEPOT = Path(__file__).resolve().parent.parent
MODELE = "https://github.com/Marplestrange/cassandra-module-modele"


def charger(nom):
    spec = importlib.util.spec_from_file_location(nom, DEPOT / "outils" / (nom + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sh(*cmd, cwd=None):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if r.returncode:
        raise SystemExit("échec : %s\n%s" % (" ".join(map(str, cmd)), (r.stderr or r.stdout).strip()[:300]))
    return r.stdout.strip()


def cle(dossier: Path, nom: str):
    priv = dossier / (nom + ".pem")
    sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv))
    return priv, sh("openssl", "pkey", "-in", str(priv), "-pubout").replace("\r", "") + "\n"


def etape(n, texte):
    print("\n[%d] %s" % (n, texte))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cassandra", required=True, help="le dépôt de Cassandra (CN_main.py), qui fabrique les paquets")
    a = p.parse_args(argv)
    R, V = charger("registre"), charger("verifier_independant")
    avant = R.RACINE
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        try:
            etape(1, "un dépôt de registre jetable, deux racines jetables, un éditeur jetable « acme »")
            R.RACINE = t / "registre"
            for d in ("cles", "editeurs", "docs/modules", "provenance", "avis"):
                (R.RACINE / d).mkdir(parents=True)
            principale, pub_p = cle(t, "racine-principale")
            _secours, pub_s = cle(t, "racine-secours")
            (R.RACINE / "cles" / "racine-principale.pub").write_text(pub_p, encoding="utf-8")
            (R.RACINE / "cles" / "racine-secours.pub").write_text(pub_s, encoding="utf-8")
            editeur, pub_e = cle(t, "acme")
            (R.RACINE / "editeurs" / "acme.toml").write_text('id = "acme"\nnom = "Acme"\nverifie = true\nexpire = "2099-01-01"\ncle = """%s"""\n' % pub_e, encoding="utf-8")

            etape(2, "l'éditeur clone le dépôt modèle PUBLIC (tel qu'on le trouve sur GitHub) et construit son paquet signé")
            clone = t / "modele"
            sh("git", "-c", "core.autocrlf=false", "clone", "-q", MODELE, str(clone))
            commit = sh("git", "rev-parse", "HEAD", cwd=clone)
            archive = R.RACINE / "docs" / "modules" / "acme_exemple" / "acme_exemple-0.1.0.cmod"
            archive.parent.mkdir(parents=True)
            sh(sys.executable, str(Path(a.cassandra) / "CN_main.py"), "paquet", "construire", str(clone / "acme_exemple"), "--cle", str(editeur), "--sortie", str(archive))
            (R.RACINE / "provenance" / "acme_exemple-0.1.0.toml").write_text('depot = "%s"\ncommit = "%s"\ndossier = "acme_exemple"\n' % (MODELE, commit), encoding="utf-8")
            print("    commit du modèle : %s" % commit[:12])

            etape(3, "le registre contrôle l'archive (signature, nom, analyse du code) puis la RECONSTITUE depuis GitHub")
            assert R.main(["verifier"]) == 0, "le contrôle a refusé le module de l'éditeur"
            assert R.main(["provenance"]) == 0, "la provenance n'a pas été reconstituée à l'identique depuis GitHub"

            etape(4, "publication de l'index signé, puis révocation et avis, et nouvelle publication")
            assert R.main(["publier", "--cle", str(principale)]) == 0
            (R.RACINE / "revocations.toml").write_text('[[revocation]]\nid = "acme_exemple"\nversions = "<0.1.0"\nraison = "répétition : rien n\'est réellement révoqué"\n', encoding="utf-8")
            (R.RACINE / "avis" / "AV-REP-001.toml").write_text('id = "AV-REP-001"\nmodule = "acme_exemple"\ngravite = "faible"\nresume = "Avis de répétition."\ncorrige_en = "0.1.0"\n', encoding="utf-8")
            assert R.main(["publier", "--cle", str(principale)]) == 0
            brut = json.loads((R.RACINE / "docs" / "index.json").read_text(encoding="utf-8"))
            assert brut["serie"] == 2 and brut["revocations"] and brut["avis"], "l'index doit porter la série 2, la révocation et l'avis"
            print("    série %d, %d révocation(s), %d avis" % (brut["serie"], len(brut["revocations"]), len(brut["avis"])))

            etape(5, "le vérificateur indépendant (clés jetables posées à la place des vraies) reconnaît l'authentique et refuse le trafiqué")
            V.RACINES = {"principale": pub_p, "secours": pub_s}
            assert V.main(["--base", str(R.RACINE / "docs"), "--module", "acme_exemple"]) == 0, "le vérificateur aurait dû tout reconnaître"
            f = R.RACINE / "docs" / "index.json"
            trafique = json.loads(f.read_text(encoding="utf-8"))
            trafique["modules"][0]["sha256"] = "0" * 64
            f.write_text(json.dumps(trafique), encoding="utf-8")
            assert V.main(["--base", str(R.RACINE / "docs")]) == 1, "le vérificateur aurait dû refuser un index modifié"
        finally:
            R.RACINE = avant
        shutil.rmtree(t / "modele", ignore_errors=True)
    print("\nRÉPÉTITION RÉUSSIE : le parcours complet d'un éditeur tiers fonctionne contre GitHub, sans toucher au vrai registre.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
