#!/usr/bin/env python3
"""Outil du registre officiel de Cassandra : contrôler le dépôt, publier l'index signé.

    python outils/registre.py verifier                       contrôle tout (archives, éditeurs, révocations, index publié) ; code 1 au moindre défaut
    python outils/registre.py publier --cle racine.pem       contrôle, puis écrit docs/index.json, docs/index.json.sig et la vitrine docs/index.html
                             [--jours 60]                    (la clé privée reste HORS de ce dépôt : sur ta machine, hors ligne ; l'intégration continue ne signe jamais)

Autonome (bibliothèque standard + openssl) : il tourne dans l'intégration continue sans rien installer. Les contrôles ici sont ceux d'un registre ;
l'examen complet d'un module (dépendances, conflits, permissions) est refait par Cassandra à chaque installation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
FORMAT = 1
MAX_ARCHIVE = 32 * 2 ** 20
MAX_FICHIERS, MAX_OCTETS = 2000, 64 * 2 ** 20
_ID = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_VERSION = re.compile(r"^\d+(\.\d+){1,3}$")
_NOM_ARCHIVE = re.compile(r"^([a-z][a-z0-9_]{1,40})-(\d+(?:\.\d+){1,3})\.cmod$")
_PEM = re.compile(r"^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]{40,200}-----END PUBLIC KEY-----\n?$")
IMPORTANCES = ("vital", "important", "optionnel")


class Defaut(Exception):
    pass


def openssl(*args) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["openssl", *args], capture_output=True, timeout=30)
    except FileNotFoundError as ex:
        raise Defaut("openssl est nécessaire") from ex


def version_de(t) -> tuple:
    return tuple(int(x) for x in str(t).split(".") if x.isdigit()) or (0,)


# ── les clés ────────────────────────────────────────────────────────────────────
def cles_racine() -> dict:
    d = {f.stem: f.read_text(encoding="utf-8") for f in sorted((RACINE / "cles").glob("*.pub"))}
    if not d:
        raise Defaut("aucune clé racine dans cles/ : le dépôt ne peut rien vérifier")
    for nom, pem in d.items():
        if not _PEM.match(pem.replace("\r", "")):
            raise Defaut("cles/%s.pub n'est pas une clé publique PEM" % nom)
    return d


def editeurs() -> dict:
    """{id : {nom, cle, site}} des éditeurs déclarés vérifiés (editeurs/<id>.toml)."""
    sortie = {}
    for f in sorted((RACINE / "editeurs").glob("*.toml")):
        try:
            d = tomllib.loads(f.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as ex:
            raise Defaut("%s : TOML illisible (%s)" % (f.name, ex))
        if f.stem != d.get("id") or not _ID.match(str(d.get("id", ""))):
            raise Defaut("%s : « id » doit être le nom du fichier, en minuscules (a-z 0-9 _)" % f.name)
        if d["id"] == "cassandra":
            raise Defaut("%s : « cassandra » est réservé à la racine" % f.name)
        if d.get("verifie") is not True:
            continue                                                     # une candidature non vérifiée n'est pas publiée
        cle = str(d.get("cle", "")).replace("\r", "")
        if not _PEM.match(cle):
            raise Defaut("%s : « cle » doit être une clé publique PEM" % f.name)
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "k").write_text(cle, encoding="utf-8")
            if openssl("pkey", "-pubin", "-in", str(Path(t) / "k"), "-noout").returncode != 0:
                raise Defaut("%s : la clé n'est pas une clé publique valide" % f.name)
        sortie[d["id"]] = {"nom": str(d.get("nom") or d["id"])[:60], "cle": cle, "site": str(d.get("site", ""))[:120]}
    return sortie


def revocations() -> list:
    f = RACINE / "revocations.toml"
    if not f.is_file():
        return []
    try:
        d = tomllib.loads(f.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as ex:
        raise Defaut("revocations.toml : TOML illisible (%s)" % ex)
    sortie = []
    for x in d.get("revocation", []):
        if not isinstance(x, dict) or not _ID.match(str(x.get("id", ""))):
            raise Defaut("revocations.toml : une révocation sans « id » valide")
        v = str(x.get("versions", "")).strip()
        if v and not re.match(r"^((>=|<=|==|>|<)\s*\d+(\.\d+){0,3}\s*,?\s*)+$", v):
            raise Defaut("revocations.toml : « versions » mal écrit pour %s (exemple : « <2.0 »)" % x["id"])
        if not str(x.get("raison", "")).strip():
            raise Defaut("revocations.toml : la raison est obligatoire pour %s (on doit pouvoir dire pourquoi)" % x["id"])
        sortie.append({"id": x["id"], "versions": v, "raison": str(x["raison"]).strip()[:300]})
    return sortie


def signature_ok(octets: bytes, brut: bytes, cles: dict) -> str:
    """Le nom de la clé de `cles` qui a signé `octets` (signature brute de 64 octets), ou ""."""
    if len(brut) != 64:
        return ""
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "m").write_bytes(octets)
        (t / "s").write_bytes(brut)
        for nom, pem in cles.items():
            (t / "k").write_text(pem, encoding="utf-8")
            if openssl("pkeyutl", "-verify", "-pubin", "-inkey", str(t / "k"), "-rawin", "-in", str(t / "m"), "-sigfile", str(t / "s")).returncode == 0:
                return nom
    return ""


# ── une archive ─────────────────────────────────────────────────────────────────
def sommes(dossier: Path) -> bytes:
    lignes = []
    for p in sorted(dossier.rglob("*")):
        if p.is_symlink():
            raise Defaut("lien symbolique refusé : %s" % p.relative_to(dossier))
        if p.is_file():
            lignes.append("%s  %s" % (hashlib.sha256(p.read_bytes()).hexdigest(), p.relative_to(dossier).as_posix()))
    return ("\n".join(lignes) + "\n").encode("utf-8")


def extraire(archive: Path, dest: Path):
    """(dossier du module, SOMMES, SIGNATURE) ; refuse tout ce qui sort du dossier, tout lien, toute démesure."""
    if archive.stat().st_size > MAX_ARCHIVE:
        raise Defaut("archive de plus de %d Mo" % (MAX_ARCHIVE // 2 ** 20))
    try:
        tar = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError, EOFError) as ex:
        raise Defaut("archive illisible : %s" % ex)
    racines, total = set(), 0
    with tar:
        membres = tar.getmembers()
        if len(membres) > MAX_FICHIERS:
            raise Defaut("archive démesurée (plus de %d fichiers)" % MAX_FICHIERS)
        for ti in membres:
            total += max(ti.size, 0)
            parts = Path(ti.name).parts
            if total > MAX_OCTETS or ti.name.startswith("/") or ".." in parts or not parts:
                raise Defaut("chemin refusé ou archive démesurée : %s" % ti.name)
            if not (ti.isfile() or ti.isdir()):
                raise Defaut("seuls les fichiers et les dossiers sont permis (refusé : %s)" % ti.name)
            if parts[0] not in ("SOMMES", "SIGNATURE"):
                racines.add(parts[0])
        if len(racines) != 1:
            raise Defaut("un seul dossier de module est attendu")
        base = dest.resolve()
        for ti in membres:
            cible = dest / ti.name
            if base not in cible.resolve().parents and cible.resolve() != base:
                raise Defaut("chemin refusé : %s" % ti.name)
            if ti.isdir():
                cible.mkdir(parents=True, exist_ok=True)
            else:
                cible.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(ti) as src, open(cible, "wb") as dst:
                    shutil.copyfileobj(src, dst)
    mod = dest / next(iter(racines))
    somm, sig = dest / "SOMMES", dest / "SIGNATURE"
    if not somm.is_file() or not sig.is_file():
        raise Defaut("SOMMES et SIGNATURE sont obligatoires : un paquet du registre est toujours signé")
    return mod, somm.read_bytes(), sig.read_bytes()


def controler_archive(chemin: Path, racines: dict, eds: dict) -> dict:
    """Les contrôles d'UNE archive ; rend ses faits (pour l'index) ou lève Defaut."""
    m = _NOM_ARCHIVE.match(chemin.name)
    if not m or chemin.parent.name != m.group(1):
        raise Defaut("nom attendu : modules/<id>/<id>-<version>.cmod")
    mid, version = m.groups()
    with tempfile.TemporaryDirectory() as t:
        mod, somm, sig = extraire(chemin, Path(t))
        if mod.name != mid:
            raise Defaut("le dossier du module (%s) diffère de l'identifiant du nom de fichier (%s)" % (mod.name, mid))
        if sommes(mod) != somm:
            raise Defaut("le contenu ne correspond pas à SOMMES : l'archive a été modifiée depuis sa signature")
        f = mod / "CN_manifeste.toml"
        if not f.is_file():
            raise Defaut("CN_manifeste.toml absent")
        try:
            man = tomllib.loads(f.read_text(encoding="utf-8"))["module"]
        except (tomllib.TOMLDecodeError, KeyError) as ex:
            raise Defaut("manifeste illisible : %s" % ex)
        if man.get("id") != mid or str(man.get("version")) != version:
            raise Defaut("le manifeste dit %s %s, le nom de fichier dit %s %s" % (man.get("id"), man.get("version"), mid, version))
        if man.get("confiance") == "interne":
            raise Defaut("la confiance « interne » est réservée aux modules livrés avec le noyau")
        for k in ("nom", "description", "famille"):
            if not str(man.get(k, "")).strip():
                raise Defaut("le manifeste doit dire « %s »" % k)
        if man.get("importance") not in IMPORTANCES or not str(man.get("sans", "")).strip():
            raise Defaut("le manifeste doit déclarer « importance » (%s) et « sans » (ce qui s'arrête sans le module)" % ", ".join(IMPORTANCES))
        cles = {("cassandra-" + k): v for k, v in racines.items()}
        cles.update({("ed_" + k): v["cle"] for k, v in eds.items()})
        qui = signature_ok(somm, sig, cles)
        if not qui:
            raise Defaut("signature absente de la liste : ni une clé racine (cles/), ni un éditeur vérifié (editeurs/)")
        editeur = "cassandra" if qui.startswith("cassandra-") else qui[3:]
        octets = chemin.read_bytes()
        requiert = []
        for x in man.get("requiert", []) or []:
            mm = re.match(r"^([a-z][a-z0-9_]{1,40})", str(x))
            if mm:
                requiert.append(mm.group(1))
        return {"id": mid, "nom": str(man["nom"])[:80], "version": version, "description": str(man["description"]).strip()[:500], "famille": str(man.get("famille", ""))[:40],
                "auteur": str(man.get("auteur", ""))[:80], "licence": str(man.get("licence", ""))[:40], "importance": man["importance"], "sans": str(man["sans"])[:300],
                "noyau_min": str(man.get("noyau_min", ""))[:20], "requiert": requiert, "icone_trace": str(man.get("icone_trace", ""))[:800],
                "taille": len(octets), "sha256": hashlib.sha256(octets).hexdigest(), "editeur": editeur,
                "url": "modules/%s/%s" % (mid, chemin.name)}


def archives() -> list:
    return sorted((RACINE / "docs" / "modules").glob("*/*.cmod"))


def tout_controler():
    """(les modules à publier — la dernière version de chacun —, les éditeurs, les révocations) ; lève Defaut."""
    racines, eds, rev = cles_racine(), editeurs(), revocations()
    faits, defauts = [], []
    for a in archives():
        try:
            faits.append(controler_archive(a, racines, eds))
        except Defaut as ex:
            defauts.append("%s : %s" % (a.relative_to(RACINE).as_posix(), ex))
    if defauts:
        raise Defaut("\n".join(defauts))
    derniers = {}
    for f in faits:
        if f["id"] not in derniers or version_de(f["version"]) > version_de(derniers[f["id"]]["version"]):
            derniers[f["id"]] = f
    return sorted(derniers.values(), key=lambda f: f["id"]), eds, rev


# ── l'index ─────────────────────────────────────────────────────────────────────
def construire_index(modules: list, eds: dict, rev: list, jours: int, maintenant: float | None = None) -> bytes:
    now = int(time.time() if maintenant is None else maintenant)
    brut = {"format": FORMAT, "emis": now, "expire": now + jours * 86400, "modules": modules,
            "editeurs": [{"id": k, "nom": v["nom"], "verifie": True, "cle": v["cle"], "site": v["site"]} for k, v in sorted(eds.items())], "revocations": rev}
    return (json.dumps(brut, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


def signer(octets: bytes, cle_privee: Path) -> bytes:
    with tempfile.TemporaryDirectory() as t:
        (Path(t) / "m").write_bytes(octets)
        r = openssl("pkeyutl", "-sign", "-inkey", str(cle_privee), "-rawin", "-in", str(Path(t) / "m"), "-out", str(Path(t) / "s"))
        if r.returncode != 0:
            raise Defaut("signature impossible : %s" % r.stderr.decode("utf-8", "replace")[:150])
        return base64.b64encode((Path(t) / "s").read_bytes()) + b"\n"


def cle_privee_connue(cle_privee: Path, racines: dict) -> str:
    r = openssl("pkey", "-in", str(cle_privee), "-pubout")
    if r.returncode != 0:
        raise Defaut("clé privée illisible")
    pub = r.stdout.decode().replace("\r", "").strip()
    nom = next((k for k, v in racines.items() if v.replace("\r", "").strip() == pub), "")
    if not nom:
        raise Defaut("cette clé privée ne correspond à aucune clé racine de cles/ : l'index signé serait refusé par toutes les installations")
    return nom


def verifier_index_publie(racines: dict):
    f, s = RACINE / "docs" / "index.json", RACINE / "docs" / "index.json.sig"
    if not f.is_file() and not s.is_file():
        return
    if not (f.is_file() and s.is_file()):
        raise Defaut("docs/index.json et docs/index.json.sig vont ensemble")
    try:
        sig = base64.b64decode(s.read_bytes().strip(), validate=True)
    except ValueError:
        raise Defaut("docs/index.json.sig n'est pas du base64")
    if not signature_ok(f.read_bytes(), sig, racines):
        raise Defaut("la signature de docs/index.json ne correspond à aucune clé racine : l'index a été modifié sans être resigné")
    brut = json.loads(f.read_text(encoding="utf-8"))
    listes = {(x["id"], x["version"]): x["sha256"] for x in brut.get("modules", [])}
    for (mid, v), sha in listes.items():
        a = RACINE / "docs" / "modules" / mid / ("%s-%s.cmod" % (mid, v))
        if not a.is_file():
            raise Defaut("l'index liste %s %s, dont l'archive manque" % (mid, v))
        if hashlib.sha256(a.read_bytes()).hexdigest() != sha:
            raise Defaut("l'archive %s %s ne correspond plus à l'empreinte de l'index signé" % (mid, v))


# ── la vitrine ──────────────────────────────────────────────────────────────────
def vitrine(brut: dict) -> str:
    eds = {e["id"]: e for e in brut["editeurs"]}
    cartes = []
    for m in brut["modules"]:
        off = m["editeur"] == "cassandra"
        niveau = "Officiel" if off else "Éditeur vérifié · " + html.escape(eds.get(m["editeur"], {}).get("nom", m["editeur"]))
        cartes.append('<article class="m"><h3>%s</h3><p class="id">%s · v%s</p><p>%s</p><p class="pied"><span class="n %s">%s</span><span>%s</span><span>%d Ko</span></p></article>'
                      % (html.escape(m["nom"]), html.escape(m["id"]), html.escape(m["version"]), html.escape(m["description"]), "off" if off else "ver", niveau, html.escape(m["importance"]), max(1, m["taille"] // 1024)))
    rev = "".join("<li><b>%s</b> %s : %s</li>" % (html.escape(r["id"]), html.escape(r["versions"] or "toutes les versions"), html.escape(r["raison"])) for r in brut["revocations"])
    return """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Registre officiel de Cassandra</title>
<style>
:root{--bg:#eef3f2;--fg:#14302d;--soft:#4b6663;--card:#fff;--line:rgba(15,40,38,.13);--accent:#0f766e}
@media (prefers-color-scheme:dark){:root{--bg:#0c1816;--fg:#d6ebe7;--soft:#9cbab5;--card:#16302c;--line:rgba(190,240,230,.16);--accent:#2dd4bf}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,'Segoe UI',sans-serif;padding:28px max(16px,env(safe-area-inset-left))}
main{max-width:980px;margin:0 auto}h1{font-size:26px;margin:0 0 6px}.sous{color:var(--soft);max-width:62ch}
.grille{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin:22px 0}
.m{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px}.m h3{margin:0}.m p{margin:.35em 0}.id{font:12px ui-monospace,Menlo,monospace;color:var(--soft)}
.pied{display:flex;gap:10px;flex-wrap:wrap;font-size:12.5px;color:var(--soft)}.n{font-weight:600;border-radius:99px;padding:1px 9px;border:1px solid var(--line)}.n.off{color:var(--accent);border-color:var(--accent)}
.note{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 16px;color:var(--soft);font-size:14px}code{font:13px ui-monospace,Menlo,monospace}
</style></head><body><main>
<h1>Registre officiel de Cassandra</h1>
<p class="sous">Les modules que l'application Cassandra peut installer depuis son App Store. Chaque archive est signée ; l'index lui-même est signé par la clé racine de Cassandra : une copie modifiée est refusée.</p>
<div class="grille">%s</div>
<div class="note"><b>Pour installer</b> : dans Cassandra, menu avatar › App Store › Registre. Rien ne s'installe sans votre accord ; un module tourne <b>dans</b> Cassandra : lisez ce qu'il demande avant de consentir.<br>
Index émis le %s, valable jusqu'au %s. Source et règles : <a href="https://github.com/Marplestrange/cassandra-registre">dépôt du registre</a>.</div>
%s
</main></body></html>
""" % ("".join(cartes) or '<p class="sous">Aucun module publié pour l\'instant.</p>', time.strftime("%d/%m/%Y", time.gmtime(brut["emis"])), time.strftime("%d/%m/%Y", time.gmtime(brut["expire"])),
       ('<h2>Révocations</h2><ul>%s</ul>' % rev) if rev else "")


# ── les commandes ───────────────────────────────────────────────────────────────
def cmd_verifier(_):
    modules, eds, rev = tout_controler()
    verifier_index_publie(cles_racine())
    print("OK : %d module(s), %d éditeur(s) vérifié(s), %d révocation(s)" % (len(modules), len(eds), len(rev)))


def cmd_publier(a):
    racines = cles_racine()
    cle = Path(a.cle)
    if not cle.is_file():
        raise Defaut("clé privée introuvable : %s" % cle)
    nom = cle_privee_connue(cle, racines)
    modules, eds, rev = tout_controler()
    octets = construire_index(modules, eds, rev, a.jours)
    sig = signer(octets, cle)
    docs = RACINE / "docs"
    (docs / "index.json").write_bytes(octets)
    (docs / "index.json.sig").write_bytes(sig)
    (docs / "index.html").write_text(vitrine(json.loads(octets)), encoding="utf-8")
    (docs / ".nojekyll").write_text("", encoding="utf-8")
    verifier_index_publie(racines)
    print("publié : %d module(s), signé par la clé « %s », valable %d jours" % (len(modules), nom, a.jours))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("verifier").set_defaults(f=cmd_verifier)
    q = sp.add_parser("publier")
    q.add_argument("--cle", required=True, help="la clé privée racine (PEM Ed25519), hors du dépôt")
    q.add_argument("--jours", type=int, default=60, help="durée de validité de l'index (60 par défaut) : à renouveler avant")
    q.set_defaults(f=cmd_publier)
    a = p.parse_args(argv)
    try:
        a.f(a)
    except Defaut as ex:
        print("REFUSÉ :\n%s" % ex, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
