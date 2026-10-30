"""Le banc de l'outil du registre : ce qu'il accepte, ce qu'il refuse, et qu'un index modifié ou périmé ne passe pas."""
import base64
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

DEPOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("registre", DEPOT / "outils" / "registre.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

MANIFESTE = '''[module]
id = "{id}"
nom = "Module {id}"
version = "{version}"
noyau_min = "0.1.0"
description = "Un module d'essai."
confiance = "local"
famille = "autres"
importance = "optionnel"
sans = "Rien de grave."
{plus}'''


def cle(dossier: Path, nom: str):
    priv = dossier / (nom + ".pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)], check=True, capture_output=True)
    pub = subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout"], check=True, capture_output=True).stdout.decode().replace("\r", "")
    return priv, pub


def archive(dest: Path, priv: Path, mid="essai", version="1.0.0", plus="", nom_fichier=None, alterer=False):
    """Une archive .cmod signée, au même format que celle de Cassandra."""
    src = Path(tempfile.mkdtemp()) / mid
    src.mkdir()
    (src / "CN_manifeste.toml").write_text(MANIFESTE.format(id=mid, version=version, plus=plus), encoding="utf-8")
    (src / "CN_module.py").write_text("def brancher(ctx):\n    pass\n", encoding="utf-8")
    somm = R.sommes(src)
    sig = Path(tempfile.mkdtemp()) / "s"
    m = Path(sig.parent / "m")
    m.write_bytes(somm)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-rawin", "-in", str(m), "-out", str(sig)], check=True, capture_output=True)
    if alterer:                                                       # on change le code APRÈS avoir signé
        (src / "CN_module.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    cible = dest / "docs" / "modules" / mid / (nom_fichier or "%s-%s.cmod" % (mid, version))
    cible.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(cible, "w:gz") as tar:
        for p in sorted(src.rglob("*")):
            tar.add(p, arcname=(Path(mid) / p.relative_to(src)).as_posix())
        for nom, donnees in (("SOMMES", somm), ("SIGNATURE", sig.read_bytes())):
            ti = tarfile.TarInfo(nom)
            ti.size = len(donnees)
            tar.addfile(ti, io.BytesIO(donnees))
    return cible


class Ambiance:
    """Le dépôt d'essai : une racine, un dossier temporaire, un éditeur. Sans tests : les bancs qui s'en servent l'héritent sans rejouer ceux des autres."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / "cles").mkdir()
        (self.d / "editeurs").mkdir()
        (self.d / "docs" / "modules").mkdir(parents=True)
        self.priv, pub = cle(self.d, "racine")
        (self.d / "cles" / "racine-principale.pub").write_text(pub, encoding="utf-8")
        ancien = R.RACINE
        R.RACINE = self.d
        self.addCleanup(lambda: setattr(R, "RACINE", ancien))

    def editeur(self, eid="acme", verifie=True):
        priv, pub = cle(self.d, eid)
        (self.d / "editeurs" / (eid + ".toml")).write_text('id = "%s"\nnom = "Acme"\nverifie = %s\ncle = """%s"""\n' % (eid, "true" if verifie else "false", pub), encoding="utf-8")
        return priv


class Depot(Ambiance, unittest.TestCase):
    def test_une_archive_signee_par_la_racine_passe_et_se_publie_signee(self):
        archive(self.d, self.priv)
        self.assertEqual(R.main(["verifier"]), 0)
        self.assertEqual(R.main(["publier", "--cle", str(self.priv)]), 0)
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual([(m["id"], m["editeur"]) for m in brut["modules"]], [("essai", "cassandra")])
        self.assertTrue((self.d / "docs" / "index.json.sig").is_file())
        self.assertTrue((self.d / "docs" / "index.html").is_file())
        self.assertEqual(R.main(["verifier"]), 0)

    def test_un_editeur_verifie_est_accepte_une_candidature_non_verifiee_non(self):
        archive(self.d, self.editeur(verifie=True), mid="acme_outil")
        (self.d / "provenance").mkdir()
        (self.d / "provenance" / "acme_outil-1.0.0.toml").write_text('depot = "https://github.com/acme/outil"\ncommit = "%s"\n' % ("a" * 40), encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 0)
        shutil.rmtree(self.d / "docs" / "modules" / "acme_outil")
        (self.d / "editeurs" / "acme.toml").unlink()
        archive(self.d, self.editeur(verifie=False), mid="acme_outil")
        self.assertEqual(R.main(["verifier"]), 1)                                   # sa clé n'est pas publiée : l'archive est signée par un inconnu

    def test_une_cle_inconnue_une_archive_alteree_un_mauvais_nom_sont_refuses(self):
        inconnue, _ = cle(self.d, "inconnue")
        archive(self.d, inconnue, mid="intrus")
        self.assertEqual(R.main(["verifier"]), 1)
        shutil.rmtree(self.d / "docs" / "modules" / "intrus")
        archive(self.d, self.priv, mid="trafique", alterer=True)
        self.assertEqual(R.main(["verifier"]), 1)
        shutil.rmtree(self.d / "docs" / "modules" / "trafique")
        archive(self.d, self.priv, mid="mal", version="1.0.0", nom_fichier="mal-2.0.0.cmod")
        self.assertEqual(R.main(["verifier"]), 1)

    def test_un_manifeste_sans_importance_ou_interne_est_refuse(self):
        global MANIFESTE
        sauve = MANIFESTE
        try:
            MANIFESTE = sauve.replace('confiance = "local"', 'confiance = "interne"')
            archive(self.d, self.priv, mid="interne")
            self.assertEqual(R.main(["verifier"]), 1)
            shutil.rmtree(self.d / "docs" / "modules" / "interne")
            MANIFESTE = sauve.replace('importance = "optionnel"\n', "")
            archive(self.d, self.priv, mid="sansimp")
            self.assertEqual(R.main(["verifier"]), 1)
        finally:
            MANIFESTE = sauve

    def test_un_index_modifie_apres_signature_est_detecte(self):
        archive(self.d, self.priv)
        R.main(["publier", "--cle", str(self.priv)])
        f = self.d / "docs" / "index.json"
        brut = json.loads(f.read_text(encoding="utf-8"))
        brut["modules"][0]["sha256"] = "0" * 64
        f.write_text(json.dumps(brut), encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 1)

    def test_une_archive_remplacee_apres_publication_ne_correspond_plus_a_l_index(self):
        archive(self.d, self.priv, version="1.0.0")
        R.main(["publier", "--cle", str(self.priv)])
        a = self.d / "docs" / "modules" / "essai" / "essai-1.0.0.cmod"
        autre = archive(Path(tempfile.mkdtemp()), self.priv, version="1.0.0", plus="# autre\n")
        shutil.copy(autre, a)
        self.assertEqual(R.main(["verifier"]), 1)

    def test_publier_avec_une_cle_qui_n_est_pas_la_racine_est_refuse(self):
        archive(self.d, self.priv)
        autre, _ = cle(self.d, "autre")
        self.assertEqual(R.main(["publier", "--cle", str(autre)]), 1)
        self.assertFalse((self.d / "docs" / "index.json").exists())

    def test_seule_la_derniere_version_est_listee(self):
        archive(self.d, self.priv, version="1.0.0")
        archive(self.d, self.priv, version="1.10.0")
        archive(self.d, self.priv, version="1.9.0")
        R.main(["publier", "--cle", str(self.priv)])
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual([m["version"] for m in brut["modules"]], ["1.10.0"])                  # 1.10 > 1.9 : les versions se comparent par nombres

    def test_une_revocation_sans_raison_est_refusee(self):
        (self.d / "revocations.toml").write_text('[[revocation]]\nid = "mauvais"\nversions = "<2.0"\n', encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 1)
        (self.d / "revocations.toml").write_text('[[revocation]]\nid = "mauvais"\nversions = "<2.0"\nraison = "lit les fichiers du voisin"\n', encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 0)

    def test_le_depot_reel_est_valide(self):
        R.RACINE = DEPOT
        self.assertEqual(R.main(["verifier"]), 0)


if __name__ == "__main__":
    unittest.main()
