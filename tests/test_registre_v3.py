"""Le banc de la rotation des clés, du vérificateur indépendant et de l'analyse (faux positifs) : ce qui rend le registre vérifiable sans nous croire."""
import importlib.util
import json
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_registre as T                                              # noqa: E402
import test_registre_v2 as V2                                          # noqa: E402

R = T.R
DEPOT = T.DEPOT


def charger(nom):
    spec = importlib.util.spec_from_file_location(nom, DEPOT / "outils" / (nom + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Rotation(V2.Base, unittest.TestCase):
    def cles(self):
        """Deux racines nommées comme les vraies : racine-principale (self.priv) et racine-secours."""
        secours, pub = T.cle(self.d, "secours")
        (self.d / "cles" / "racine-secours.pub").write_text(pub, encoding="utf-8")
        nouvelle, pub_n = T.cle(self.d, "nouvelle")
        return secours, nouvelle, pub_n

    def annoncer(self, pub_nouvelle, raison="répétition à blanc"):
        (self.d / "rotation.toml").write_text('nouvelle_cle = """%s"""\nraison = "%s"\n' % (pub_nouvelle, raison), encoding="utf-8")

    def test_une_rotation_ne_se_publie_qu_avec_la_cle_de_secours(self):
        secours, _nouvelle, pub_n = self.cles()
        T.archive(self.d, self.priv)
        self.annoncer(pub_n)
        self.assertEqual(R.main(["publier", "--cle", str(self.priv)]), 1)          # la principale ne peut pas s'annoncer elle-même un remplaçant
        self.assertEqual(R.main(["publier", "--cle", str(secours)]), 0)
        brut = json.loads((self.d / "docs" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual((brut["rotation"]["nom"], brut["rotation"]["retire"], brut["rotation"]["cle"].strip()), ("principale", ["principale"], pub_n.strip()))

    def test_une_rotation_sans_raison_ou_avec_une_mauvaise_cle_est_refusee(self):
        secours, _n, pub_n = self.cles()
        T.archive(self.d, self.priv)
        (self.d / "rotation.toml").write_text('nouvelle_cle = """%s"""\n' % pub_n, encoding="utf-8")
        self.assertEqual(R.main(["publier", "--cle", str(secours)]), 1)
        (self.d / "rotation.toml").write_text('nouvelle_cle = "pas une clé"\nraison = "x"\n', encoding="utf-8")
        self.assertEqual(R.main(["publier", "--cle", str(secours)]), 1)

    def test_apres_la_rotation_le_depot_se_verifie_avec_la_nouvelle_cle_une_fois_publiee_dans_cles(self):
        secours, nouvelle, pub_n = self.cles()
        T.archive(self.d, self.priv)
        self.annoncer(pub_n)
        R.main(["publier", "--cle", str(secours)])
        (self.d / "cles" / "racine-principale.pub").write_text(pub_n, encoding="utf-8")       # le geste humain qui suit : la nouvelle clé remplace l'ancienne dans cles/
        (self.d / "rotation.toml").unlink()
        self.assertEqual(R.main(["verifier"]), 1)                                              # les archives signées par l'ANCIENNE principale ne valent plus : il faut les resigner
        shutil.rmtree(self.d / "docs" / "modules" / "essai")
        T.archive(self.d, nouvelle)
        self.assertEqual(R.main(["verifier"]), 1)                                              # l'index publié liste encore l'ancienne archive : à republier
        self.assertEqual(R.main(["publier", "--cle", str(nouvelle)]), 0)
        self.assertEqual(R.main(["verifier"]), 0)
        self.assertEqual(R.main(["publier", "--cle", str(self.priv)]), 1)                      # l'ancienne n'est plus une racine du dépôt


class Verificateur(V2.Base, unittest.TestCase):
    def test_le_verificateur_independant_reconnait_un_registre_authentique_et_refuse_un_registre_trafique(self):
        v = charger("verifier_independant")
        T.archive(self.d, self.priv)
        R.main(["publier", "--cle", str(self.priv)])
        # le script a les VRAIES clés racine : un registre signé par une clé d'essai doit donc être refusé, jamais accepté
        self.assertEqual(v.main(["--base", str(self.d / "docs"), "--module", "essai"]), 1)
        # avec les clés d'essai posées à la place des vraies, il reconnaît ce qui est authentique…
        v.RACINES = {"principale": (self.d / "cles" / "racine-principale.pub").read_text(encoding="utf-8")}
        self.assertEqual(v.main(["--base", str(self.d / "docs"), "--module", "essai"]), 0)
        # …et refuse un index modifié après signature
        f = self.d / "docs" / "index.json"
        brut = json.loads(f.read_text(encoding="utf-8"))
        brut["modules"][0]["sha256"] = "0" * 64
        f.write_text(json.dumps(brut), encoding="utf-8")
        self.assertEqual(v.main(["--base", str(self.d / "docs"), "--module", "essai"]), 1)

    def test_les_cles_du_verificateur_sont_celles_du_depot(self):
        v = charger("verifier_independant")
        for nom, pem in v.RACINES.items():
            self.assertEqual(pem.strip(), (DEPOT / "cles" / ("racine-%s.pub" % nom)).read_text(encoding="utf-8").replace("\r", "").strip(), nom)


class Analyse(V2.Base, unittest.TestCase):
    def test_re_compile_et_les_appels_ordinaires_ne_sont_pas_du_code_dynamique(self):
        d = Path(self.tmp.name) / "m"
        d.mkdir()
        (d / "a.py").write_text("import re\nX = re.compile('a+')\n\ndef f(s):\n    return X.match(s)\n", encoding="utf-8")
        erreurs, alertes = R.analyser(d, {})
        self.assertEqual((erreurs, alertes), ([], []))

    def test_eval_nu_est_signale_et_os_system_demande_une_permission(self):
        d = Path(self.tmp.name) / "m2"
        d.mkdir()
        (d / "a.py").write_text("import os\n\ndef f(s):\n    os.system('ls')\n    return eval(s)\n", encoding="utf-8")
        erreurs, alertes = R.analyser(d, {})
        self.assertTrue(any("processus" in e for e in erreurs))
        self.assertTrue(any("eval" in a for a in alertes))
        erreurs, _ = R.analyser(d, {"racine": True})
        self.assertEqual(erreurs, [])

    def test_les_modules_du_depot_ne_font_pas_d_alerte_inutile(self):
        R.RACINE = DEPOT
        racines, eds = R.cles_racine(), R.editeurs()
        for a in R.archives():
            f = R.controler_archive(a, racines, eds)
            self.assertEqual(f["alertes"], [], "%s %s" % (f["id"], f["alertes"]))


if __name__ == "__main__":
    unittest.main()
