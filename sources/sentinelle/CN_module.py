# ══════════════════════════════════════════════════════════════════════════════
# TITRE      : Sentinelle du disque
# LICENCE    : AGPL-3.0
# AUTEUR     : Atek Drisse
# GIT        : github.com/Marplestrange
# MAIL       : marplestrange@cassandra.center
# MODULE     : exemples
# ZONE       : CN
# VERSION CN : 0.1.0  #f9a348
# VERSION EC : néant
# EC LIÉES   : néant
# RÔLE       : Sentinelle du disque : l'exemple le plus court d'une greffe.
# MÉTHODE    : à compléter par l'auteur (comment le fichier s'y prend)
# ══════════════════════════════════════════════════════════════════════════════
# ▼▼▼ BORNE CN version=0.1.0 empreinte=f9a348 ▼▼▼
"""Sentinelle du disque : l'exemple le plus court d'une greffe.

Un moteur périodique mesure, un détecteur ouvre un constat, un type d'objet donne une fiche au registre.
Rien ici n'ouvre de thread, n'importe un autre module ni n'écrit hors de ce que le manifeste déclare.
"""
import shutil

SEUIL = 90.0


def brancher(ctx):
    def mesurer(ctx):
        u = shutil.disk_usage("/")
        pct = round(100.0 * u.used / u.total, 1)
        ctx.poser("disque", "/", "Disque racine", etat="plein" if pct >= SEUIL else "ok",
                  donnees={"pct": pct, "libre_go": round(u.free / 2 ** 30, 1)})
        ctx.emettre("disque.mesure", objet=("disque", "/"), donnees={"pct": pct})

    def plein(ctx):
        d = ctx.lire("disque", "/", portee=ctx.TOUT)
        if d and d["etat"] == "plein":
            return [{"objet": ("disque", "/"), "titre": "Disque racine occupé à %s %%" % d["donnees"]["pct"]}]
        return []

    def lire_mesure(ctx):
        d = ctx.lire("disque", "/", portee=ctx.TOUT)
        return d["donnees"] if d else None

    ctx.implementer("lire_mesure", lire_mesure)
    ctx.moteur("mesurer", mesurer)
    ctx.detecteur("disque_plein", plein)
# ▲▲▲ FIN BORNE CN ▲▲▲

# ═══ EXPLICATIF CN / EC ═══════════════════════════════════════════════════════
# CN : tout ce fichier est du nexus : brancher
# EC : néant (aucun point d'évolution déclaré pour l'instant)
# LIEN : à compléter (contrat, fichiers voisins)
