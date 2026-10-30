#!/bin/sh
# ══════════════════════════════════════════════════════════════════════════════
# TITRE      : La preuve
# LICENCE    : AGPL-3.0
# AUTEUR     : Atek Drisse
# GIT        : github.com/Marplestrange
# MAIL       : marplestrange@cassandra.center
# MODULE     : exemples
# ZONE       : CN
# VERSION CN : 0.1.0  #737fbd
# VERSION EC : néant
# EC LIÉES   : néant
# RÔLE       : La preuve : la mesure dont la sentinelle dépend fonctionne sur cette machine.
# MÉTHODE    : à compléter par l'auteur (comment le fichier s'y prend)
# ══════════════════════════════════════════════════════════════════════════════
# ▼▼▼ BORNE CN version=0.1.0 empreinte=737fbd ▼▼▼
# La preuve : la mesure dont la sentinelle dépend fonctionne sur cette machine.
df -P / >/dev/null 2>&1 || { echo "sentinelle : df ne répond pas" >&2; exit 1; }
echo "sentinelle : df répond"
exit 0
# ▲▲▲ FIN BORNE CN ▲▲▲

# ═══ EXPLICATIF CN / EC ═══════════════════════════════════════════════════════
# CN : tout ce fichier est du nexus : à compléter
# EC : néant (aucun point d'évolution déclaré pour l'instant)
# LIEN : à compléter (contrat, fichiers voisins)
