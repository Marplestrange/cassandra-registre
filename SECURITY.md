# Security policy

*Version française complète : [SECURITE.md](SECURITE.md).*

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Write to **marplestrange@cassandra.center**, or use GitHub's private vulnerability reporting (Security tab › *Report a vulnerability*). Include the module and version if it concerns a module, and how to reproduce it.

We aim to acknowledge a report within a few days. A dangerous module is **revoked without waiting** (every installation then refuses it, with the reason shown publicly), and a machine-readable advisory is published in `avis/`. Please do not disclose the problem before it is fixed.

## What this registry guarantees — and what it does not

- Every module archive is signed and the catalogue (index) itself is signed; a replayed older index is refused; the index is kept fresh by a low-privilege key.
- A third-party publisher's code can be read exactly as published (provenance rebuilt by CI), and is statically checked against its declared permissions.
- **An installed module runs inside Cassandra with its rights.** The signature says *who* published it; only a review says *what the code does*. Process-level isolation does not exist yet.

You can check all of this yourself, without trusting our tools: `python outils/verifier_independant.py`.

## Supported versions

Only the current published index and the current Cassandra release are supported.
