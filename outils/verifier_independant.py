#!/usr/bin/env python3
"""Vérifier le registre SANS faire confiance à nos outils : un script court, lisible en dix minutes, qui ne dépend que de Python et d'openssl.

    python outils/verifier_independant.py                         vérifie le registre publié (https://marplestrange.github.io/cassandra-registre/)
    python outils/verifier_independant.py --base docs             vérifie une copie locale (ou un miroir : --base https://…/)
    python outils/verifier_independant.py --module billetterie    vérifie aussi l'archive de ce module (empreinte, puis signature de son contenu)

Il ne lit PAS les clés dans ce dépôt : les deux clés racine sont écrites dans ce fichier, avec leur empreinte. Comparez ces empreintes à celles que vous trouvez ailleurs
(README, site, annonce publique) : si elles concordent, vous vérifiez bien contre la clé de Cassandra, quoi qu'on ait mis dans le dépôt. Code de sortie 0 : tout est authentique.
"""
import argparse
import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

URL = "https://marplestrange.github.io/cassandra-registre/"
RACINES = {
    "principale": """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+cKesWjI5Zt2PBUaAE1ZPYK8ZLu+9MSu+W2zj4yek1g=
-----END PUBLIC KEY-----
""",
    "secours": """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAccbKbL0DNQ585E44qW9G44qBygDeIHiPjwsPMPLPQAo=
-----END PUBLIC KEY-----
""",
}


def lire(base: str, chemin: str) -> bytes:
    if base.startswith("http"):
        with urllib.request.urlopen(urllib.request.Request(base.rstrip("/") + "/" + chemin, headers={"User-Agent": "verifier-independant"}), timeout=30) as r:
            return r.read()
    return (Path(base) / chemin).read_bytes()


def empreinte(pem: str) -> str:
    der = base64.b64decode("".join(l for l in pem.splitlines() if not l.startswith("-----")))
    return hashlib.sha256(der).hexdigest()


def signature_ok(message: bytes, sig_b64: bytes, cles: dict) -> str:
    """Le nom de la clé qui a signé `message`, ou ''. Ed25519, par openssl."""
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except ValueError:
        return ""
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "m").write_bytes(message)
        (t / "s").write_bytes(sig)
        for nom, pem in cles.items():
            (t / "k").write_text(pem, encoding="utf-8")
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(t / "k"), "-rawin", "-in", str(t / "m"), "-sigfile", str(t / "s")], capture_output=True)
            if r.returncode == 0:
                return nom
    return ""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default=URL)
    p.add_argument("--module")
    a = p.parse_args(argv)
    mal = []

    def dire(ok, texte):
        print(("  ok   " if ok else "  FAUX ") + texte)
        if not ok:
            mal.append(texte)

    print("Clés racine embarquées dans ce script (comparez-les à celles publiées ailleurs) :")
    for n, k in RACINES.items():
        print("  %-10s SHA-256 de la clé : %s" % (n, empreinte(k)))
    index, sig = lire(a.base, "index.json"), lire(a.base, "index.json.sig")
    qui = signature_ok(index, sig, RACINES)
    dire(bool(qui), "l'index est signé par la clé racine « %s »" % qui if qui else "la signature de l'index ne correspond à aucune clé racine")
    if not qui:
        return 1
    brut = json.loads(index)
    now = time.time()
    dire(brut.get("expire", 0) > now, "l'index n'a pas expiré (expire le %s)" % time.strftime("%d/%m/%Y", time.gmtime(brut.get("expire", 0))))
    print("  série %s, émis le %s, %d module(s), %d révocation(s)" % (brut.get("serie", "?"), time.strftime("%d/%m/%Y", time.gmtime(brut.get("emis", 0))), len(brut["modules"]), len(brut["revocations"])))
    fr = brut.get("fraicheur")
    if fr:
        try:
            f, fs = lire(a.base, "fraicheur.json"), lire(a.base, "fraicheur.json.sig")
            d = json.loads(f)
            ok = (signature_ok(f, fs, {"fraicheur": fr["cle"]}) and d.get("serie") == brut.get("serie") and d.get("index_sha256") == hashlib.sha256(index).hexdigest() and d.get("expire", 0) > now)
        except Exception as ex:                                       # noqa: BLE001 : toute défaillance est un « FAUX »
            ok = False
        dire(bool(ok), "la fraîcheur (clé annoncée par l'index) atteste cet index et n'est pas périmée")
    for r in brut["revocations"]:
        print("  révoqué : %s %s — %s" % (r["id"], r.get("versions") or "toutes les versions", r["raison"]))
    if a.module:
        m = next((x for x in brut["modules"] + brut.get("beta", []) + brut.get("progressifs", []) if x["id"] == a.module), None)
        if not m:
            print("  le module « %s » n'est pas dans l'index" % a.module)
            return 1
        archive = lire(a.base, m["url"])
        dire(hashlib.sha256(archive).hexdigest() == m["sha256"], "l'empreinte de %s correspond à celle de l'index signé" % m["url"])
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            somm, sg = tar.extractfile("SOMMES").read(), tar.extractfile("SIGNATURE").read()
        cles = {"racine-" + k: v for k, v in RACINES.items()}
        cles.update({"editeur-" + e["id"]: e["cle"] for e in brut["editeurs"]})
        q = signature_ok(somm, base64.b64encode(sg), cles)
        dire(bool(q), "le contenu de l'archive est signé par « %s »" % q if q else "la signature du contenu ne correspond à aucune clé connue")
    print("\nTOUT EST AUTHENTIQUE" if not mal else "\n%d VÉRIFICATION(S) ÉCHOUÉE(S)" % len(mal))
    return 1 if mal else 0


if __name__ == "__main__":
    sys.exit(main())
