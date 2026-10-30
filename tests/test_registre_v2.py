"""Le banc des nouveautés du registre : analyse du code, provenance, espace de noms, canaux, journal chaîné, série, fraîcheur, avis, vitrine."""
import hashlib
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_registre as T                                              # noqa: E402

R = T.R


class Base(T.Ambiance):
    def archive_avec(self, priv, mid, code, plus="", version="1.0.0"):
        """Une archive signée dont le code (CN_module.py) est celui donné."""
        src = Path(tempfile.mkdtemp()) / mid
        src.mkdir()
        (src / "CN_manifeste.toml").write_text(T.MANIFESTE.format(id=mid, version=version, plus=plus), encoding="utf-8")
        (src / "CN_module.py").write_text(code, encoding="utf-8")
        somm = R.sommes(src)
        t = Path(tempfile.mkdtemp())
        (t / "m").write_bytes(somm)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-rawin", "-in", str(t / "m"), "-out", str(t / "s")], check=True, capture_output=True)
        cible = self.d / "docs" / "modules" / mid / ("%s-%s.cmod" % (mid, version))
        cible.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(cible, "w:gz") as tar:
            for p in sorted(src.rglob("*")):
                tar.add(p, arcname=(Path(mid) / p.relative_to(src)).as_posix())
            for nom, donnees in (("SOMMES", somm), ("SIGNATURE", (t / "s").read_bytes())):
                ti = tarfile.TarInfo(nom)
                ti.size = len(donnees)
                tar.addfile(ti, io.BytesIO(donnees))
        return cible

    def provenance(self, mid, version="1.0.0"):
        (self.d / "provenance").mkdir(exist_ok=True)
        (self.d / "provenance" / ("%s-%s.toml" % (mid, version))).write_text('depot = "https://github.com/acme/outil"\ncommit = "%s"\n' % ("b" * 40), encoding="utf-8")


class Analyse(Base, unittest.TestCase):
    def test_un_module_d_editeur_qui_parle_au_reseau_sans_le_dire_est_refuse(self):
        ed = self.editeur()
        self.archive_avec(ed, "acme_net", "import urllib.request\n\ndef brancher(ctx):\n    urllib.request.urlopen('http://x')\n")
        self.provenance("acme_net")
        self.assertEqual(R.main(["verifier"]), 1)

    def test_le_meme_module_qui_declare_son_reseau_passe(self):
        ed = self.editeur()
        self.archive_avec(ed, "acme_net", "import urllib.request\n\ndef brancher(ctx):\n    pass\n", '[permissions]\nreseau = ["l\'API de Acme"]\n')
        self.provenance("acme_net")
        self.assertEqual(R.main(["verifier"]), 0)

    def test_ctypes_et_code_masque_sont_refuses_aux_tiers(self):
        ed = self.editeur()
        self.archive_avec(ed, "acme_c", "import ctypes\n\ndef brancher(ctx):\n    pass\n")
        self.provenance("acme_c")
        self.assertEqual(R.main(["verifier"]), 1)
        shutil.rmtree(self.d / "docs" / "modules" / "acme_c")
        self.archive_avec(ed, "acme_m", "import base64\n\ndef brancher(ctx):\n    exec(base64.b64decode('cGFzcw=='))\n")
        self.provenance("acme_m")
        self.assertEqual(R.main(["verifier"]), 1)

    def test_un_module_officiel_n_est_pas_bloque_mais_l_alerte_est_dite(self):
        self.archive_avec(self.priv, "officiel_net", "import socket\n\ndef brancher(ctx):\n    pass\n")
        self.assertEqual(R.main(["verifier"]), 0)
        R.main(["publier", "--cle", str(self.priv)])
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertTrue(any("socket" in a for a in brut["modules"][0]["alertes"]))

    def test_un_fichier_python_illisible_est_refuse(self):
        ed = self.editeur()
        self.archive_avec(ed, "acme_casse", "def brancher(ctx:\n")
        self.provenance("acme_casse")
        self.assertEqual(R.main(["verifier"]), 1)


class EspaceDeNomsEtProvenance(Base, unittest.TestCase):
    def test_un_editeur_ne_prend_pas_le_nom_d_un_autre(self):
        ed = self.editeur()
        T.archive(self.d, ed, mid="sentinelle")
        self.provenance("sentinelle")
        self.assertEqual(R.main(["verifier"]), 1)

    def test_un_module_d_editeur_sans_provenance_est_refuse(self):
        ed = self.editeur()
        T.archive(self.d, ed, mid="acme_outil")
        self.assertEqual(R.main(["verifier"]), 1)
        self.provenance("acme_outil")
        self.assertEqual(R.main(["verifier"]), 0)

    def test_une_provenance_mal_formee_est_refusee(self):
        (self.d / "provenance").mkdir()
        (self.d / "provenance" / "essai-1.0.0.toml").write_text('depot = "ftp://x"\ncommit = "abc"\n', encoding="utf-8")
        T.archive(self.d, self.priv)
        self.assertEqual(R.main(["verifier"]), 1)

    def test_une_cle_d_editeur_expiree_n_est_plus_publiee(self):
        ed = self.editeur()
        f = self.d / "editeurs" / "acme.toml"
        f.write_text(f.read_text(encoding="utf-8") + 'expire = "2000-01-01"\n', encoding="utf-8")
        T.archive(self.d, ed, mid="acme_outil")
        self.provenance("acme_outil")
        self.assertEqual(R.main(["verifier"]), 1)                       # sa clé a expiré : la signature n'est plus reconnue


class Journal(Base, unittest.TestCase):
    def publier(self):
        self.assertEqual(R.main(["publier", "--cle", str(self.priv)]), 0)

    def test_la_serie_croit_et_le_journal_se_chaine(self):
        T.archive(self.d, self.priv)
        self.publier()
        self.publier()
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(brut["serie"], 2)
        lignes = [json.loads(x) for x in (self.d / "journal.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([l["serie"] for l in lignes], [1, 2])
        self.assertEqual(lignes[1]["prec"], lignes[0]["ligne"])
        self.assertEqual(R.main(["verifier"]), 0)

    def test_retirer_ou_modifier_une_ligne_du_journal_est_detecte(self):
        T.archive(self.d, self.priv)
        self.publier()
        self.publier()
        f = self.d / "journal.jsonl"
        lignes = f.read_text(encoding="utf-8").splitlines()
        f.write_text(lignes[1] + "\n", encoding="utf-8")                # la première ligne a disparu
        self.assertEqual(R.main(["verifier"]), 1)
        l0 = json.loads(lignes[0])
        l0["modules"] = {"autre": "9.9.9:x"}
        f.write_text(json.dumps(l0) + "\n" + lignes[1] + "\n", encoding="utf-8")   # une ligne modifiée
        self.assertEqual(R.main(["verifier"]), 1)

    def test_un_index_qui_n_est_pas_la_derniere_ligne_du_journal_est_detecte(self):
        T.archive(self.d, self.priv)
        self.publier()
        j = (self.d / "journal.jsonl").read_text(encoding="utf-8")
        lg = json.loads(j.splitlines()[-1])
        lg["index_sha256"] = "0" * 64
        lg["ligne"] = R.empreinte_ligne(lg)
        (self.d / "journal.jsonl").write_text(json.dumps(lg) + "\n", encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 1)


class CanauxEtAvis(Base, unittest.TestCase):
    def test_une_beta_n_est_pas_offerte_a_tous_et_un_deploiement_progressif_garde_la_precedente(self):
        T.archive(self.d, self.priv, version="1.0.0")
        T.archive(self.d, self.priv, version="1.1.0")
        T.archive(self.d, self.priv, version="1.2.0")
        (self.d / "canaux.toml").write_text('[[publication]]\nid = "essai"\nversion = "1.1.0"\ncanal = "stable"\npourcent = 25\n[[publication]]\nid = "essai"\nversion = "1.2.0"\ncanal = "beta"\n', encoding="utf-8")
        R.main(["publier", "--cle", str(self.priv)])
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual([m["version"] for m in brut["modules"]], ["1.0.0"])             # tout le monde reçoit la dernière à 100 %
        self.assertEqual([(m["version"], m["pourcent"]) for m in brut["progressifs"]], [("1.1.0", 25)])
        self.assertEqual([m["version"] for m in brut["beta"]], ["1.2.0"])

    def test_un_canal_inconnu_ou_une_version_sans_archive_est_refuse(self):
        T.archive(self.d, self.priv)
        (self.d / "canaux.toml").write_text('[[publication]]\nid = "essai"\nversion = "1.0.0"\ncanal = "nightly"\n', encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 1)
        (self.d / "canaux.toml").write_text('[[publication]]\nid = "essai"\nversion = "9.9.9"\ncanal = "beta"\n', encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 1)

    def test_un_avis_bien_forme_est_publie_un_avis_sans_gravite_est_refuse(self):
        T.archive(self.d, self.priv)
        (self.d / "avis").mkdir()
        (self.d / "avis" / "AV-2026-001.toml").write_text('id = "AV-2026-001"\nmodule = "essai"\ngravite = "haute"\nresume = "Lit hors de son espace."\nversions_touchees = "<1.1"\ncorrige_en = "1.1.0"\n', encoding="utf-8")
        R.main(["publier", "--cle", str(self.priv)])
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual([a["id"] for a in brut["avis"]], ["AV-2026-001"])
        (self.d / "avis" / "AV-2026-001.toml").write_text('id = "AV-2026-001"\nmodule = "essai"\nresume = "x"\n', encoding="utf-8")
        self.assertEqual(R.main(["verifier"]), 1)


class FraicheurEtVitrine(Base, unittest.TestCase):
    def init_fraicheur(self):
        priv, pub = T.cle(self.d, "fraicheur")
        (self.d / "fraicheur").mkdir()
        (self.d / "fraicheur" / "fraicheur.pub").write_text(pub, encoding="utf-8")
        return priv

    def signer(self, priv, **modif):
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        d = {"serie": brut["serie"], "index_sha256": hashlib.sha256((self.d / "docs" / "index.json").read_bytes()).hexdigest(), "emis": int(time.time()), "expire": int(time.time()) + 3600}
        d.update(modif)
        octets = json.dumps(d).encode("utf-8")
        (self.d / "docs" / "fraicheur.json").write_bytes(octets)
        (self.d / "docs" / "fraicheur.json.sig").write_bytes(R.signer(octets, priv))

    def test_un_index_qui_annonce_une_fraicheur_sans_elle_est_signale(self):
        T.archive(self.d, self.priv)
        fr = self.init_fraicheur()
        R.main(["publier", "--cle", str(self.priv)])
        self.assertEqual(R.main(["verifier"]), 1)                       # la fraîcheur manque
        self.signer(fr)
        self.assertEqual(R.main(["verifier"]), 0)

    def test_une_fraicheur_perimee_d_un_autre_index_ou_d_une_autre_cle_est_refusee(self):
        T.archive(self.d, self.priv)
        fr = self.init_fraicheur()
        R.main(["publier", "--cle", str(self.priv)])
        self.signer(fr, expire=int(time.time()) - 10)
        self.assertEqual(R.main(["verifier"]), 1)
        self.signer(fr, serie=99)
        self.assertEqual(R.main(["verifier"]), 1)
        autre, _ = T.cle(self.d, "autre2")
        self.signer(autre)
        self.assertEqual(R.main(["verifier"]), 1)

    def test_la_vitrine_a_ses_filtres_et_une_page_par_module(self):
        T.archive(self.d, self.priv, plus='[permissions]\nreseau = ["un service"]\n')
        R.main(["publier", "--cle", str(self.priv)])
        accueil = (self.d / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="q"', accueil)
        self.assertIn('href="modules/essai/"', accueil)
        self.assertIn("assets/logo-maison-boheme.png", accueil)                 # le pied dit qui porte le projet, avec son logo
        self.assertIn("La Maison Bohème", accueil)
        page = (self.d / "docs" / "modules" / "essai" / "index.html").read_text(encoding="utf-8")
        self.assertIn("un service", page)
        self.assertIn("sha256sum", page)
        self.assertIn("../../assets/logo-maison-boheme.png", page)

    def test_la_commande_vitrine_ne_touche_ni_a_l_index_ni_a_la_signature(self):
        T.archive(self.d, self.priv)
        R.main(["publier", "--cle", str(self.priv)])
        avant = ((self.d / "docs" / "index.json").read_bytes(), (self.d / "docs" / "index.json.sig").read_bytes())
        self.assertEqual(R.main(["vitrine"]), 0)
        self.assertEqual(avant, ((self.d / "docs" / "index.json").read_bytes(), (self.d / "docs" / "index.json.sig").read_bytes()))


if __name__ == "__main__":
    unittest.main()
