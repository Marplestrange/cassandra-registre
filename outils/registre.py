#!/usr/bin/env python3
"""Outil du registre officiel de Cassandra : contrôler le dépôt, publier l'index signé.

    python outils/registre.py verifier                       contrôle tout (archives, éditeurs, révocations, index publié) ; code 1 au moindre défaut
    python outils/registre.py publier --cle racine.pem       contrôle, puis écrit docs/index.json (série suivante), docs/index.json.sig, la vitrine et une page par module, et ajoute au journal
    python outils/registre.py vitrine                        réécrit la vitrine depuis l'index déjà publié (ne signe rien)
    python outils/registre.py provenance                     reconstitue chaque archive qui déclare sa source et la compare, fichier par fichier
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
CANAUX = ("stable", "beta")
GRAVITES = ("faible", "moyenne", "haute", "critique")
VALIDITE_FRAICHEUR_S = 14 * 86400                                      # une fraîcheur signée vaut deux semaines (une machine éteinte pendant des vacances ne bloque pas le registre) : au-delà, l'index n'est plus cru
CHEMIN_FRAICHEUR = "fraicheur"                                         # dossier de la clé publique de fraîcheur (hors de cles/ : ce n'est PAS une racine)
IMPORTS_RESEAU = {"socket", "ssl", "urllib", "http", "ftplib", "smtplib", "imaplib", "poplib", "telnetlib", "requests", "httpx", "aiohttp", "websockets", "xmlrpc", "websocket"}
IMPORTS_DANGEREUX = {"ctypes", "pty"}                                  # jamais utiles à un module : ils sortent de tout périmètre
IMPORTS_OBSCURCISSEMENT = {"marshal", "zlib", "base64", "codecs", "binascii"}
APPELS_CODE_DYNAMIQUE = {"eval", "exec", "compile", "__import__"}
APPELS_PROCESSUS = {"system", "popen", "popen2", "popen3", "execv", "execve", "execl", "execlp", "execvp", "spawnl", "spawnv"}


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
        fin = str(d.get("expire", "")).strip()
        if fin:                                                          # une clé d'éditeur a une durée de vie : passé la date, elle n'est plus publiée (et ses archives se voient refusées)
            try:
                if time.mktime(time.strptime(fin, "%Y-%m-%d")) < time.time():
                    continue
            except ValueError:
                raise Defaut("%s : « expire » s'écrit AAAA-MM-JJ" % f.name)
        cle = str(d.get("cle", "")).replace("\r", "")
        if not _PEM.match(cle):
            raise Defaut("%s : « cle » doit être une clé publique PEM" % f.name)
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "k").write_text(cle, encoding="utf-8")
            if openssl("pkey", "-pubin", "-in", str(Path(t) / "k"), "-noout").returncode != 0:
                raise Defaut("%s : la clé n'est pas une clé publique valide" % f.name)
        sortie[d["id"]] = {"nom": str(d.get("nom") or d["id"])[:60], "cle": cle, "site": str(d.get("site", ""))[:120], "expire": fin, "contact": str(d.get("contact", ""))[:120]}
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


def avis() -> list:
    """Les avis de sécurité (avis/<id>.toml) : ce que l'on sait d'une faille, lisible par une machine. Une révocation EMPÊCHE d'installer ; un avis INFORME (gravité, versions touchées, correctif)."""
    sortie = []
    for f in sorted((RACINE / "avis").glob("*.toml")) if (RACINE / "avis").is_dir() else []:
        try:
            d = tomllib.loads(f.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as ex:
            raise Defaut("avis/%s : TOML illisible (%s)" % (f.name, ex))
        if f.stem != str(d.get("id", "")) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,40}$", f.stem):
            raise Defaut("avis/%s : « id » doit être le nom du fichier (lettres, chiffres, - _ .)" % f.name)
        mod = str(d.get("module", ""))
        if not _ID.match(mod):
            raise Defaut("avis/%s : « module » doit être l'identifiant d'un module" % f.name)
        if d.get("gravite") not in GRAVITES:
            raise Defaut("avis/%s : « gravite » parmi %s" % (f.name, ", ".join(GRAVITES)))
        for k in ("resume",):
            if not str(d.get(k, "")).strip():
                raise Defaut("avis/%s : « %s » est obligatoire" % (f.name, k))
        v = str(d.get("versions_touchees", "")).strip()
        if v and not re.match(r"^((>=|<=|==|>|<)\s*\d+(\.\d+){0,3}\s*,?\s*)+$", v):
            raise Defaut("avis/%s : « versions_touchees » mal écrit (exemple : « <1.2 »)" % f.name)
        sortie.append({"id": f.stem, "module": mod, "gravite": d["gravite"], "resume": str(d["resume"]).strip()[:400], "versions_touchees": v,
                       "corrige_en": str(d.get("corrige_en", ""))[:20], "cve": str(d.get("cve", ""))[:40], "date": str(d.get("date", ""))[:10]})
    return sortie


def publications() -> dict:
    """canaux.toml : à quel canal appartient une version (stable par défaut) et à quel pourcentage des installations elle est proposée (100 par défaut)."""
    f = RACINE / "canaux.toml"
    if not f.is_file():
        return {}
    try:
        d = tomllib.loads(f.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as ex:
        raise Defaut("canaux.toml : TOML illisible (%s)" % ex)
    sortie = {}
    for x in d.get("publication", []):
        if not isinstance(x, dict) or not _ID.match(str(x.get("id", ""))) or not _VERSION.match(str(x.get("version", ""))):
            raise Defaut("canaux.toml : une publication sans « id » et « version » valides")
        canal, pct = x.get("canal", "stable"), x.get("pourcent", 100)
        if canal not in CANAUX:
            raise Defaut("canaux.toml : « canal » parmi %s (%s %s)" % (", ".join(CANAUX), x["id"], x["version"]))
        if not isinstance(pct, int) or isinstance(pct, bool) or not 1 <= pct <= 100:
            raise Defaut("canaux.toml : « pourcent » est un entier de 1 à 100 (%s %s)" % (x["id"], x["version"]))
        sortie[(x["id"], str(x["version"]))] = {"canal": canal, "pourcent": pct}
    return sortie


def provenance_de(mid: str, version: str) -> dict:
    """provenance/<id>-<version>.toml : d'où vient le code de cette archive (dépôt public et commit), pour qu'on puisse le relire tel qu'il est publié."""
    f = RACINE / "provenance" / ("%s-%s.toml" % (mid, version))
    if not f.is_file():
        return {}
    try:
        d = tomllib.loads(f.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as ex:
        raise Defaut("provenance/%s : TOML illisible (%s)" % (f.name, ex))
    depot, commit, dossier = str(d.get("depot", "")), str(d.get("commit", "")), str(d.get("dossier", "")).strip("/")
    if not re.match(r"^https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,200}$", depot) or not re.match(r"^[0-9a-f]{40}$", commit):
        raise Defaut("provenance/%s : « depot » (https) et « commit » (40 caractères hexadécimaux) sont obligatoires" % f.name)
    if ".." in Path(dossier).parts or dossier.startswith("/"):
        raise Defaut("provenance/%s : « dossier » sort du dépôt" % f.name)
    return {"depot": depot, "commit": commit, "dossier": dossier}


def analyser(mod: Path, perm: dict) -> tuple:
    """(erreurs, alertes) : ce que le code d'un module fait et que son manifeste n'a pas déclaré. Une erreur ferme la porte à un module de tiers ;
    pour un module officiel, tout reste une alerte à lire. Ce n'est PAS une preuve d'innocuité : c'est un filtre devant la relecture humaine."""
    import ast
    perm = perm if isinstance(perm, dict) else {}
    reseau_declare = bool(perm.get("reseau"))
    processus_declare = bool(perm.get("racine") or perm.get("privileges"))
    erreurs, alertes = [], []
    for f in sorted(mod.rglob("*.py")):
        rel = f.relative_to(mod).as_posix()
        try:
            arbre = ast.parse(f.read_text(encoding="utf-8"), filename=rel)
        except (SyntaxError, UnicodeDecodeError, ValueError) as ex:
            erreurs.append("%s : illisible comme du Python (%s)" % (rel, str(ex)[:60]))
            continue
        importes, appels = set(), []
        for n in ast.walk(arbre):
            if isinstance(n, ast.Import):
                importes.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                importes.add(n.module.split(".")[0])
            elif isinstance(n, ast.Call):
                nom = n.func.id if isinstance(n.func, ast.Name) else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
                appels.append((nom, getattr(n.func, "value", None)))
        noms = {a for a, _ in appels}
        dang = importes & IMPORTS_DANGEREUX
        if dang:
            erreurs.append("%s : importe %s (hors de tout périmètre)" % (rel, ", ".join(sorted(dang))))
        dyn = noms & APPELS_CODE_DYNAMIQUE
        if dyn and importes & IMPORTS_OBSCURCISSEMENT:
            erreurs.append("%s : code dynamique (%s) à côté d'un décodage (%s) : code masqué" % (rel, ", ".join(sorted(dyn)), ", ".join(sorted(importes & IMPORTS_OBSCURCISSEMENT))))
        elif dyn:
            alertes.append("%s : exécute du code dynamique (%s)" % (rel, ", ".join(sorted(dyn))))
        res = importes & IMPORTS_RESEAU
        if res and not reseau_declare:
            erreurs.append("%s : parle au réseau (%s) sans l'avoir déclaré dans [permissions] reseau" % (rel, ", ".join(sorted(res))))
        proc = ("subprocess" in importes) or bool(noms & APPELS_PROCESSUS)
        if proc and not processus_declare:
            erreurs.append("%s : lance des processus sans l'avoir déclaré dans [permissions] (racine ou privileges)" % rel)
    return erreurs, alertes


def changelog_de(mod: Path) -> str:
    for nom in ("CN_CHANGELOG.md", "CHANGELOG.md"):
        f = mod / nom
        if f.is_file():
            return f.read_text(encoding="utf-8", errors="replace").strip()[:1500]
    return ""


# ── le journal des publications : append-only, chaîné par empreintes ───────────────
def lire_journal() -> list:
    f = RACINE / "journal.jsonl"
    if not f.is_file():
        return []
    lignes = []
    for i, brut in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if not brut.strip():
            continue
        try:
            lignes.append(json.loads(brut))
        except ValueError:
            raise Defaut("journal.jsonl ligne %d : JSON illisible" % i)
    return lignes


def empreinte_ligne(l: dict) -> str:
    sans = {k: v for k, v in l.items() if k != "ligne"}
    return hashlib.sha256(json.dumps(sans, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verifier_journal():
    """Chaque ligne cite l'empreinte de la précédente et la sienne : en retirer ou en modifier une casse la chaîne. La série croît de un en un."""
    prec, serie = "", 0
    for i, l in enumerate(lire_journal(), 1):
        if l.get("prec") != prec:
            raise Defaut("journal.jsonl ligne %d : la chaîne est rompue (une ligne a été retirée ou modifiée avant elle)" % i)
        if l.get("ligne") != empreinte_ligne(l):
            raise Defaut("journal.jsonl ligne %d : son empreinte ne correspond pas à son contenu" % i)
        if l.get("serie") != serie + 1:
            raise Defaut("journal.jsonl ligne %d : la série doit croître de un en un (attendu %d, lu %s)" % (i, serie + 1, l.get("serie")))
        prec, serie = l["ligne"], l["serie"]
    return serie, prec


def ajouter_au_journal(serie: int, octets_index: bytes, modules: list, emis: int):
    _, prec = verifier_journal()
    l = {"serie": serie, "emis": emis, "index_sha256": hashlib.sha256(octets_index).hexdigest(), "modules": {m["id"]: "%s:%s" % (m["version"], m["sha256"][:16]) for m in modules}, "prec": prec}
    l["ligne"] = empreinte_ligne(l)
    with open(RACINE / "journal.jsonl", "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(l, ensure_ascii=False, sort_keys=True) + "\n")


def serie_publiee() -> int:
    f = RACINE / "docs" / "index.json"
    if not f.is_file():
        return 0
    try:
        return int(json.loads(f.read_text(encoding="utf-8")).get("serie", 0))
    except (ValueError, TypeError):
        return 0


def cle_fraicheur() -> str:
    f = RACINE / CHEMIN_FRAICHEUR / "fraicheur.pub"
    if not f.is_file():
        return ""
    pem = f.read_text(encoding="utf-8").replace("\r", "")
    if not _PEM.match(pem):
        raise Defaut("%s/fraicheur.pub n'est pas une clé publique PEM" % CHEMIN_FRAICHEUR)
    return pem


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
            doc = tomllib.loads(f.read_text(encoding="utf-8"))
            man = doc["module"]
        except (tomllib.TOMLDecodeError, KeyError) as ex:
            raise Defaut("manifeste illisible : %s" % ex)
        if man.get("id") != mid or str(man.get("version")) != version:
            raise Defaut("le manifeste dit %s %s, le nom de fichier dit %s %s" % (man.get("id"), man.get("version"), mid, version))
        if man.get("confiance") == "interne":
            raise Defaut("la confiance « interne » est réservée aux modules livrés avec le noyau")
        for k in ("nom", "description"):
            if not str(man.get(k, "")).strip():
                raise Defaut("le manifeste doit dire « %s »" % k)
        section = str(man.get("section") or man.get("famille") or "").strip()      # « section » (nom actuel) ou « famille » (ancien nom)
        if not section:
            raise Defaut("le manifeste doit dire « section » (la rubrique où le module se range)")
        if man.get("importance") not in IMPORTANCES or not str(man.get("sans", "")).strip():
            raise Defaut("le manifeste doit déclarer « importance » (%s) et « sans » (ce qui s'arrête sans le module)" % ", ".join(IMPORTANCES))
        cles = {("cassandra-" + k): v for k, v in racines.items()}
        cles.update({("ed_" + k): v["cle"] for k, v in eds.items()})
        qui = signature_ok(somm, sig, cles)
        if not qui:
            raise Defaut("signature absente de la liste : ni une clé racine (cles/), ni un éditeur vérifié (editeurs/)")
        editeur = "cassandra" if qui.startswith("cassandra-") else qui[3:]
        if editeur != "cassandra" and not mid.startswith(editeur + "_"):
            raise Defaut("un module d'éditeur porte le nom de l'éditeur : « %s_… » (pour que nul ne prenne le nom d'un autre)" % editeur)
        perm = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
        erreurs, alertes = analyser(mod, perm)
        if erreurs and editeur != "cassandra":
            raise Defaut("analyse du code : " + " ; ".join(erreurs[:4]))
        alertes = (["(officiel) " + e for e in erreurs] + alertes)[:12]
        prov = provenance_de(mid, version)
        if editeur != "cassandra" and not prov:
            raise Defaut("un module d'éditeur doit dire d'où vient son code : provenance/%s-%s.toml (dépôt public et commit)" % (mid, version))
        permissions = {k: (v if isinstance(v, bool) else [str(x)[:200] for x in v][:10] if isinstance(v, list) else str(v)[:200]) for k, v in sorted(perm.items()) if isinstance(v, (bool, str, list))}
        octets = chemin.read_bytes()
        requiert = []
        for x in man.get("requiert", []) or []:
            mm = re.match(r"^([a-z][a-z0-9_]{1,40})", str(x))
            if mm:
                requiert.append(mm.group(1))
        return {"id": mid, "nom": str(man["nom"])[:80], "version": version, "description": str(man["description"]).strip()[:500], "famille": section[:40], "section": section[:40],
                "auteur": str(man.get("auteur", ""))[:80], "licence": str(man.get("licence", ""))[:40], "importance": man["importance"], "sans": str(man["sans"])[:300],
                "noyau_min": str(man.get("noyau_min", ""))[:20], "noyau_max": str(man.get("noyau_max", ""))[:20], "api": str(man.get("api", ""))[:10], "site": str(man.get("site", ""))[:120],
                "permissions": permissions, "changelog": changelog_de(mod), "alertes": alertes, "provenance": prov, "requiert": requiert, "icone_trace": str(man.get("icone_trace", ""))[:800],
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
    pub = publications()
    connues = {(f["id"], f["version"]) for f in faits}
    for cle_ in pub:
        if cle_ not in connues:
            raise Defaut("canaux.toml : %s %s n'a pas d'archive dans docs/modules/" % cle_)
    for f in faits:
        p = pub.get((f["id"], f["version"]), {})
        f["canal"], f["pourcent"] = p.get("canal", "stable"), p.get("pourcent", 100)
        f["versions"] = sorted((g["version"] for g in faits if g["id"] == f["id"]), key=version_de, reverse=True)
    par_id = {}
    for f in faits:
        par_id.setdefault(f["id"], []).append(f)
    stables, betas, progressifs = [], [], []
    for mid, fs in sorted(par_id.items()):
        fs = sorted(fs, key=lambda f: version_de(f["version"]), reverse=True)
        pleines = [f for f in fs if f["canal"] == "stable" and f["pourcent"] == 100]
        partielles = [f for f in fs if f["canal"] == "stable" and f["pourcent"] < 100]
        offerte = pleines[0] if pleines else (partielles[0] if partielles else None)     # ce que TOUT LE MONDE reçoit
        if offerte is None:                                                              # que des bêtas : le module n'est pas encore proposé en stable
            betas.append(fs[0])
            continue
        stables.append(offerte)
        plus_recente = [f for f in partielles if version_de(f["version"]) > version_de(offerte["version"])]
        if plus_recente:
            progressifs.append(plus_recente[0])                                          # proposée à une part seulement des installations
        bt = [f for f in fs if f["canal"] == "beta" and version_de(f["version"]) > version_de(offerte["version"])]
        if bt:
            betas.append(bt[0])
    return stables, eds, rev, {"beta": betas, "progressifs": progressifs}


# ── l'index ─────────────────────────────────────────────────────────────────────
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
    j = lire_journal()
    if j:
        if brut.get("serie") != j[-1]["serie"] or hashlib.sha256(f.read_bytes()).hexdigest() != j[-1]["index_sha256"]:
            raise Defaut("l'index publié (série %s) n'est pas la dernière ligne du journal (série %s) : un index a été publié hors du journal, ou remplacé" % (brut.get("serie"), j[-1]["serie"]))
    listes = {(x["id"], x["version"]): x["sha256"] for x in brut.get("modules", []) + brut.get("beta", []) + brut.get("progressifs", [])}
    for (mid, v), sha in listes.items():
        a = RACINE / "docs" / "modules" / mid / ("%s-%s.cmod" % (mid, v))
        if not a.is_file():
            raise Defaut("l'index liste %s %s, dont l'archive manque" % (mid, v))
        if hashlib.sha256(a.read_bytes()).hexdigest() != sha:
            raise Defaut("l'archive %s %s ne correspond plus à l'empreinte de l'index signé" % (mid, v))


def verifier_fraicheur_publiee(maintenant: float | None = None):
    """Si l'index annonce une clé de fraîcheur, docs/fraicheur.json doit être signé par elle, dater de moins d'une semaine et viser CET index."""
    f = RACINE / "docs" / "index.json"
    if not f.is_file():
        return
    brut = json.loads(f.read_text(encoding="utf-8"))
    fr = brut.get("fraicheur")
    if not fr:
        return
    now = time.time() if maintenant is None else maintenant
    jf, js = RACINE / "docs" / "fraicheur.json", RACINE / "docs" / "fraicheur.json.sig"
    if not (jf.is_file() and js.is_file()):
        raise Defaut("l'index annonce une clé de fraîcheur mais docs/fraicheur.json (et .sig) manquent : les installations le refuseront")
    try:
        sig = base64.b64decode(js.read_bytes().strip(), validate=True)
    except ValueError:
        raise Defaut("docs/fraicheur.json.sig n'est pas du base64")
    if not signature_ok(jf.read_bytes(), sig, {"fraicheur": fr["cle"]}):
        raise Defaut("docs/fraicheur.json n'est pas signé par la clé de fraîcheur de l'index")
    d = json.loads(jf.read_text(encoding="utf-8"))
    if d.get("serie") != brut.get("serie") or d.get("index_sha256") != hashlib.sha256(f.read_bytes()).hexdigest():
        raise Defaut("docs/fraicheur.json vise un autre index que celui publié")
    if not isinstance(d.get("expire"), (int, float)) or d["expire"] < now:
        raise Defaut("docs/fraicheur.json a expiré : renouvelez-le (outils/fraicheur.py signer)")


# ── la vitrine : une page, des filtres, une fiche par module ───────────────────────────────
STYLE = """:root{--bg:#eef3f2;--fg:#14302d;--soft:#4b6663;--card:#fff;--line:rgba(15,40,38,.13);--accent:#0f766e;--warn:#b45309;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0c1816;--fg:#d6ebe7;--soft:#9cbab5;--card:#16302c;--line:rgba(190,240,230,.16);--accent:#2dd4bf;--warn:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,'Segoe UI',sans-serif;padding:28px 16px}
main{max-width:980px;margin:0 auto}h1{font-size:26px;margin:0 0 6px}h2{font-size:19px;margin:26px 0 8px}.sous{color:var(--soft);max-width:66ch}a{color:var(--accent)}
.outils{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.outils input,.outils select{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px;min-height:40px}
.outils input{flex:1;min-width:200px}
.grille{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin:14px 0}
.m{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;display:block;text-decoration:none;color:inherit}.m:hover{border-color:var(--accent)}.m h3{margin:0}.m p{margin:.35em 0}
.id,code{font:12.5px ui-monospace,Menlo,monospace;color:var(--soft)}
.pied{display:flex;gap:8px;flex-wrap:wrap;font-size:12.5px;color:var(--soft)}.n{font-weight:600;border-radius:99px;padding:1px 9px;border:1px solid var(--line)}.n.off{color:var(--accent);border-color:var(--accent)}
.n.beta,.n.prog{color:var(--warn);border-color:var(--warn)}.n.rev{color:var(--bad);border-color:var(--bad)}
.note{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 16px;color:var(--soft);font-size:14px;margin:14px 0}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}td,th{padding:7px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{width:32%;color:var(--soft);font-weight:600}
pre{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere}.vide{display:none}"""

NOTE_BAS = ('Index n° %d, émis le %s, valable jusqu\'au %s. Source et règles : <a href="https://github.com/Marplestrange/cassandra-registre">dépôt du registre</a>. '
            'Soutenir le projet : <a href="https://github.com/Marplestrange/cassandra-registre/blob/main/SOUTIEN.md">La Maison Bohème</a>.')


def _niveau(m: dict, eds: dict) -> tuple:
    off = m["editeur"] == "cassandra"
    return ("off" if off else "ver"), ("Officiel" if off else "Éditeur vérifié · " + eds.get(m["editeur"], {}).get("nom", m["editeur"]))


def _date(ts) -> str:
    return time.strftime("%d/%m/%Y", time.gmtime(ts))


def vitrine(brut: dict) -> str:
    eds = {e["id"]: e for e in brut["editeurs"]}
    revoques = {r["id"] for r in brut["revocations"] if not r["versions"]}
    donnees, cartes = [], []
    pcts = {m["id"]: m for m in brut.get("progressifs", [])}
    for m in sorted(brut["modules"], key=lambda m: m["nom"].lower()) + [dict(b, _beta=True) for b in brut.get("beta", [])]:
        cl, niv = _niveau(m, eds)
        etiq = '<span class="n %s">%s</span>' % (cl, html.escape(niv))
        if m.get("_beta"):
            etiq += '<span class="n beta">bêta</span>'
        if m["id"] in pcts:
            etiq += '<span class="n prog">v%s à %d %%</span>' % (html.escape(pcts[m["id"]]["version"]), pcts[m["id"]].get("pourcent", 100))
        if m["id"] in revoques:
            etiq += '<span class="n rev">révoqué</span>'
        cartes.append('<a class="m" href="modules/%s/" data-t="%s" data-s="%s" data-n="%s"><h3>%s</h3><p class="id">%s · v%s</p><p>%s</p><p class="pied">%s<span>%s</span><span>%d Ko</span></p></a>'
                      % (html.escape(m["id"]), html.escape((m["nom"] + " " + m["id"] + " " + m["description"]).lower()), html.escape(m.get("section", "")), cl, html.escape(m["nom"]),
                         html.escape(m["id"]), html.escape(m["version"]), html.escape(m["description"]), etiq, html.escape(m["importance"]), max(1, m["taille"] // 1024)))
        donnees.append(m.get("section", ""))
    sections = "".join('<option value="%s">%s</option>' % (html.escape(x), html.escape(x)) for x in sorted({x for x in donnees if x}))
    avis = brut.get("avis", [])
    bloc_avis = ("<h2>Avis de sécurité</h2><ul>%s</ul>" % "".join("<li><b>%s</b> (%s, gravité %s) : %s%s</li>" % (html.escape(a["module"]), html.escape(a["id"]), html.escape(a["gravite"]), html.escape(a["resume"]),
                 (" Corrigé en %s." % html.escape(a["corrige_en"])) if a["corrige_en"] else "") for a in avis)) if avis else ""
    rev = "".join("<li><b>%s</b> %s : %s</li>" % (html.escape(r["id"]), html.escape(r["versions"] or "toutes les versions"), html.escape(r["raison"])) for r in brut["revocations"])
    js = """var q=document.getElementById('q'),s=document.getElementById('s'),n=document.getElementById('n'),c=document.querySelectorAll('.m');
function f(){var t=q.value.toLowerCase().trim();c.forEach(function(e){var ok=(!t||e.dataset.t.indexOf(t)>-1)&&(!s.value||e.dataset.s===s.value)&&(!n.value||e.dataset.n===n.value);e.classList.toggle('vide',!ok)})}
[q,s,n].forEach(function(e){e.addEventListener('input',f)});"""
    return """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Registre officiel de Cassandra</title>
<style>@@STYLE@@</style></head><body><main>
<h1>Registre officiel de Cassandra</h1>
<p class="sous">Les modules que l'application Cassandra peut installer depuis son App Store. Chaque archive est signée ; l'index lui-même est signé par la clé racine de Cassandra : une copie modifiée est refusée.</p>
<div class="outils"><input id="q" type="search" placeholder="Chercher un module…" aria-label="Chercher"><select id="s" aria-label="Section"><option value="">Toutes les sections</option>@@SECTIONS@@</select>
<select id="n" aria-label="Niveau de confiance"><option value="">Tous les niveaux</option><option value="off">Officiel</option><option value="ver">Éditeur vérifié</option></select></div>
<div class="grille">@@CARTES@@</div>
<div class="note"><b>Pour installer</b> : dans Cassandra, menu avatar › Logithèque › Boutique. Rien ne s'installe sans votre accord ; un module tourne <b>dans</b> Cassandra : lisez ce qu'il demande avant de consentir.<br>@@BAS@@</div>
@@AVIS@@@@REV@@
</main><script>@@JS@@</script></body></html>
""".replace("@@STYLE@@", STYLE).replace("@@SECTIONS@@", sections).replace("@@CARTES@@", "".join(cartes) or '<p class="sous">Aucun module publié pour l\'instant.</p>') \
       .replace("@@BAS@@", NOTE_BAS % (brut.get("serie", 0), _date(brut["emis"]), _date(brut["expire"]))).replace("@@AVIS@@", bloc_avis) \
       .replace("@@REV@@", ("<h2>Révocations</h2><ul>%s</ul>" % rev) if rev else "").replace("@@JS@@", js)


def page_module(m: dict, brut: dict) -> str:
    eds = {e["id"]: e for e in brut["editeurs"]}
    cl, niv = _niveau(m, eds)
    lignes = [("Identifiant", "<code>%s</code>" % html.escape(m["id"])), ("Version", html.escape(m["version"])), ("Section", html.escape(m.get("section", ""))), ("Confiance", html.escape(niv)),
              ("Auteur", html.escape(m.get("auteur", "") or "—")), ("Licence", html.escape(m.get("licence", "") or "—")), ("Importance", html.escape(m["importance"])),
              ("Sans lui", html.escape(m["sans"])), ("Noyau requis", html.escape((m.get("noyau_min") or "—") + ((" à " + m["noyau_max"]) if m.get("noyau_max") else ""))),
              ("Dépend de", ", ".join("<code>%s</code>" % html.escape(x) for x in m.get("requiert", [])) or "rien"),
              ("Taille", "%d Ko" % max(1, m["taille"] // 1024)), ("Empreinte SHA-256", "<code>%s</code>" % html.escape(m["sha256"]))]
    perms = m.get("permissions", {})
    if perms:
        lignes.append(("Ce qu'il demande", "<br>".join("<b>%s</b>%s" % (html.escape(k), "" if v is True else " : " + html.escape("; ".join(v) if isinstance(v, list) else str(v))) for k, v in perms.items() if v)))
    else:
        lignes.append(("Ce qu'il demande", "aucune permission déclarée"))
    prov = m.get("provenance") or {}
    if prov:
        lignes.append(("Code source", '<a href="%s">%s</a> au commit <code>%s</code>%s' % (html.escape(prov["depot"]), html.escape(prov["depot"]), html.escape(prov["commit"][:12]), (" (dossier " + html.escape(prov["dossier"]) + ")") if prov.get("dossier") else "")))
    if m.get("site"):
        lignes.append(("Site", '<a href="%s">%s</a>' % (html.escape(m["site"]), html.escape(m["site"]))))
    alertes = ("<h2>À lire avant d'installer</h2><ul>%s</ul>" % "".join("<li>%s</li>" % html.escape(a) for a in m["alertes"])) if m.get("alertes") else ""
    av = [a for a in brut.get("avis", []) if a["module"] == m["id"]]
    avis = ("<h2>Avis de sécurité</h2><ul>%s</ul>" % "".join("<li><b>%s</b> (gravité %s) : %s</li>" % (html.escape(a["id"]), html.escape(a["gravite"]), html.escape(a["resume"])) for a in av)) if av else ""
    chg = ("<h2>Changements</h2><pre>%s</pre>" % html.escape(m["changelog"])) if m.get("changelog") else ""
    versions = "".join('<li><a href="%s-%s.cmod">%s</a></li>' % (html.escape(m["id"]), html.escape(v), html.escape(v)) for v in m.get("versions", [m["version"]]))
    return """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>@@NOM@@ — Registre de Cassandra</title><style>@@STYLE@@</style></head><body><main>
<p><a href="../../">← Tous les modules</a></p><h1>@@NOM@@</h1><p class="sous">@@DESC@@</p>
<table>@@LIGNES@@</table>@@ALERTES@@@@AVIS@@@@CHG@@
<h2>Versions</h2><ul>@@VERSIONS@@</ul>
<div class="note">Pour installer : dans Cassandra, menu avatar › Logithèque › Boutique. Vérifiez à la main : <code>sha256sum @@ID@@-@@VER@@.cmod</code> doit rendre l'empreinte ci-dessus.<br>@@BAS@@</div>
</main></body></html>
""".replace("@@STYLE@@", STYLE).replace("@@NOM@@", html.escape(m["nom"])).replace("@@DESC@@", html.escape(m["description"])).replace("@@LIGNES@@", "".join("<tr><th>%s</th><td>%s</td></tr>" % l for l in lignes)) \
       .replace("@@ALERTES@@", alertes).replace("@@AVIS@@", avis).replace("@@CHG@@", chg).replace("@@VERSIONS@@", versions).replace("@@ID@@", html.escape(m["id"])).replace("@@VER@@", html.escape(m["version"])) \
       .replace("@@BAS@@", NOTE_BAS % (brut.get("serie", 0), _date(brut["emis"]), _date(brut["expire"])))


def ecrire_vitrine(brut: dict):
    docs = RACINE / "docs"
    (docs / "index.html").write_text(vitrine(brut), encoding="utf-8")
    for m in list(brut["modules"]) + list(brut.get("beta", [])):
        d = docs / "modules" / m["id"]
        if d.is_dir():
            (d / "index.html").write_text(page_module(m, brut), encoding="utf-8")
    (docs / ".nojekyll").write_text("", encoding="utf-8")


# ── les commandes ───────────────────────────────────────────────────────────────
def cmd_verifier(_):
    modules, eds, rev, _extra = tout_controler()
    avs = avis()
    serie, _prec = verifier_journal()
    verifier_index_publie(cles_racine())
    verifier_fraicheur_publiee()
    print("OK : %d module(s), %d éditeur(s) vérifié(s), %d révocation(s), %d avis, journal à la série %d" % (len(modules), len(eds), len(rev), len(avs), serie))


def cmd_vitrine(_):
    """Réécrit la vitrine (docs/index.html et une page par module) depuis l'index DÉJÀ publié : ne signe rien, ne touche pas à l'index."""
    f = RACINE / "docs" / "index.json"
    if not f.is_file():
        raise Defaut("pas d'index publié : lancez d'abord « publier »")
    ecrire_vitrine(json.loads(f.read_text(encoding="utf-8")))
    print("vitrine réécrite depuis l'index publié (série %s)" % json.loads(f.read_text(encoding="utf-8")).get("serie", "?"))


def cmd_provenance(a):
    """Compare le code d'une archive à celui du dépôt source, au commit déclaré : ce qui est publié est ce qui est relisible."""
    racines, eds = cles_racine(), editeurs()
    resultats = []
    for arch in archives():
        m = _NOM_ARCHIVE.match(arch.name)
        prov = provenance_de(m.group(1), m.group(2))
        if not prov:
            continue
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            mod, somm, _sig = extraire(arch, t / "a")
            src = t / "src"
            for cmd in (["git", "init", "-q", str(src)], ["git", "-C", str(src), "fetch", "-q", "--depth", "1", prov["depot"], prov["commit"]], ["git", "-C", str(src), "checkout", "-q", "FETCH_HEAD"]):
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if r.returncode:
                    raise Defaut("%s : impossible de récupérer %s au commit %s (%s)" % (arch.name, prov["depot"], prov["commit"][:12], (r.stderr or r.stdout).strip()[:120]))
            dossier = src / prov["dossier"] if prov["dossier"] else src
            if not dossier.is_dir():
                raise Defaut("%s : le dossier « %s » n'existe pas dans le dépôt source" % (arch.name, prov["dossier"]))
            ecart = []
            for ligne in somm.decode("utf-8").splitlines():
                sha, _, nom = ligne.partition("  ")
                rel = nom.split("/", 1)[1] if "/" in nom else nom
                f = dossier / rel
                if not f.is_file():
                    ecart.append("%s absent de la source" % nom)
                elif hashlib.sha256(f.read_bytes()).hexdigest() != sha:
                    ecart.append("%s diffère de la source" % nom)
            if ecart:
                raise Defaut("%s : l'archive n'est pas la source au commit déclaré : %s" % (arch.name, " ; ".join(ecart[:5])))
            resultats.append(arch.name)
    print("provenance OK : %d archive(s) reconstituée(s) à l'identique depuis leur source" % len(resultats) if resultats else "aucune archive ne déclare de provenance")


def construire_index(modules: list, eds: dict, rev: list, jours: int, maintenant: float | None = None, serie: int = 1, extra: dict | None = None, avs: list | None = None, fraicheur: str = "") -> bytes:
    now = int(time.time() if maintenant is None else maintenant)
    extra = extra or {}
    brut = {"format": FORMAT, "serie": serie, "emis": now, "expire": now + jours * 86400, "modules": modules,
            "editeurs": [{"id": k, "nom": v["nom"], "verifie": True, "cle": v["cle"], "site": v["site"], "expire": v.get("expire", ""), "contact": v.get("contact", "")} for k, v in sorted(eds.items())],
            "revocations": rev, "avis": avs or [], "beta": extra.get("beta", []), "progressifs": extra.get("progressifs", [])}
    if fraicheur:
        brut["fraicheur"] = {"cle": fraicheur, "validite_s": VALIDITE_FRAICHEUR_S}
    return (json.dumps(brut, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


def cmd_publier(a):
    racines = cles_racine()
    cle = Path(a.cle)
    if not cle.is_file():
        raise Defaut("clé privée introuvable : %s" % cle)
    nom = cle_privee_connue(cle, racines)
    modules, eds, rev, extra = tout_controler()
    avs = avis()
    serie_journal, _ = verifier_journal()
    serie = max(serie_publiee(), serie_journal) + 1                           # jamais en arrière : un index plus ancien est refusé par les installations
    octets = construire_index(modules, eds, rev, a.jours, serie=serie, extra=extra, avs=avs, fraicheur=cle_fraicheur())
    sig = signer(octets, cle)
    docs = RACINE / "docs"
    brut = json.loads(octets)
    (docs / "index.json").write_bytes(octets)
    (docs / "index.json.sig").write_bytes(sig)
    ecrire_vitrine(brut)
    ajouter_au_journal(serie, octets, modules, brut["emis"])
    verifier_index_publie(racines)
    print("publié : série %d, %d module(s), signé par la clé « %s », valable %d jours%s" % (serie, len(modules), nom, a.jours,
          "" if brut.get("fraicheur") else " (sans clé de fraîcheur : voir outils/fraicheur.py)"))
    if brut.get("fraicheur"):
        print("l'index annonce une clé de fraîcheur : (re)signez docs/fraicheur.json avec outils/fraicheur.py, sinon les installations refuseront cet index.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("verifier").set_defaults(f=cmd_verifier)
    sp.add_parser("vitrine").set_defaults(f=cmd_vitrine)
    sp.add_parser("provenance").set_defaults(f=cmd_provenance)
    q = sp.add_parser("publier")
    q.add_argument("--cle", required=True, help="la clé privée racine (PEM Ed25519), hors du dépôt")
    q.add_argument("--jours", type=int, default=60, help="durée de validité de l'index (60 par défaut ; 180 si une clé de fraîcheur le garde frais)")
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
