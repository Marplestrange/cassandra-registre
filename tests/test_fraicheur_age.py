"""La machine de secours ne renouvelle la fraîcheur que si elle est vieille."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def charger():
    sys.path.insert(0, str(RACINE / "outils"))
    spec = importlib.util.spec_from_file_location("fraicheur_outil", RACINE / "outils" / "fraicheur.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class AgeFraicheur(unittest.TestCase):
    def test_recente_ou_vieille(self):
        m = charger()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "docs").mkdir()
            (Path(d) / "docs" / "fraicheur.json").write_text(json.dumps({"emis": 1000000}), encoding="utf-8")
            ancien = m.R.RACINE
            m.R.RACINE = Path(d)
            try:
                self.assertTrue(m.fraicheur_recente(10, maintenant=1000000 + 9 * 3600))
                self.assertFalse(m.fraicheur_recente(10, maintenant=1000000 + 11 * 3600))
                self.assertFalse(m.fraicheur_recente(0, maintenant=1000000))
                (Path(d) / "docs" / "fraicheur.json").write_text("pas du json", encoding="utf-8")
                self.assertFalse(m.fraicheur_recente(10, maintenant=1000000))
            finally:
                m.R.RACINE = ancien


if __name__ == "__main__":
    unittest.main()
