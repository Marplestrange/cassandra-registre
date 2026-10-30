# Contribuer / Contributing

**Français.** Publier un module, devenir éditeur vérifié, proposer une révocation ou un avis de sécurité : tout est expliqué pas à pas dans [CONTRIBUER.md](CONTRIBUER.md).
Avant de proposer quoi que ce soit, lancez `python outils/registre.py verifier` et `python outils/registre.py provenance` : tout doit être vert.
Une faille de sécurité ne se signale pas dans un ticket : voir [SECURITY.md](SECURITY.md). Les règles de conduite sont dans [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

**English.** To publish a module, become a verified publisher, or propose a revocation or a security advisory, follow [CONTRIBUER.md](CONTRIBUER.md) (French; the steps are short and the commands are the same in any language).
Run `python outils/registre.py verifier` and `python outils/registre.py provenance` first: both must pass. Report vulnerabilities privately, never in a public issue: see [SECURITY.md](SECURITY.md).

Rien n'entre dans ce registre sans relecture d'un mainteneur : un module tourne *dans* Cassandra, avec ses droits.
Nothing enters this registry without a maintainer's review: a module runs *inside* Cassandra, with its rights.
