# Cassandra Official Registry

**The module store of [Cassandra](https://github.com/Marplestrange), where every module is signed and verifiable.**

🔎 **Browse the modules: https://marplestrange.github.io/cassandra-registre/** (search, filters, one page per module)

*Version française : [README.md](README.md).*

---

## In one sentence

Cassandra is an AI that administers your servers and your work. To give it new abilities (a theme, a bridge to another piece of software, a business domain) you install **modules**. This repository is the official list of those modules, and the proof that each one really comes from who it says it comes from.

## Why it exists

A module **runs inside Cassandra, with its rights**. Installing a module means trusting its author. Before installing, you must be able to answer three questions:

1. **Who wrote it?** Every module is signed: by the Cassandra team ("Official") or by a publisher whose identity has been checked ("Verified publisher").
2. **Is it the original code?** An archive modified after signing is rejected. A third-party publisher's code must also match its public repository, so you can read it exactly as published.
3. **What does it ask for?** Each module page lists what the module says it does (talk to the network, start processes…). A module that does more than it declares is rejected.

And if a module turns out to be dangerous, it is **revoked**: every Cassandra installation knows and refuses to install it.

## Installing a module

In Cassandra: avatar menu › **Logithèque** (the app store) › **Boutique**. Nothing is installed without your consent, and Cassandra shows you what the module asks for first.

## What protects you (no jargon)

| Risk | What prevents it |
|---|---|
| A fake module posing as another | every archive is **signed**; a publisher only publishes under its own name (`<publisher>_module`) |
| A module tampered with on the way | the **hash** of every file is checked at install time |
| A rogue site serving a fake catalogue | **the catalogue itself is signed**; Cassandra knows the key and rejects everything else |
| An old catalogue replayed to hide a withdrawn module | each catalogue has a **number that never goes backwards**; Cassandra refuses an older number |
| An abandoned registry still believed to be current | the catalogue **expires**, and a freshness proof is renewed every day |
| A module doing more than announced | its code is **analysed** against its declared permissions before publication |
| A hosting outage | **mirrors** can serve the same catalogue (everything is signed, so they need not be trusted) |

What the registry does **not** guarantee: an installed module runs with Cassandra's rights. The signature says *who* published; only a review says *what the code does*. See [SECURITE.md](SECURITE.md) (French) for details.

## Verify it yourself

Do not take our word for it: a short script that needs only Python and openssl, and does not use our tools, verifies the published registry.

```
python outils/verifier_independant.py --module billetterie
```

It hard-codes the two root keys. Compare their **fingerprints** (SHA-256 of the public key) to the ones below and to those announced elsewhere (website, public posts): if they match, you are verifying against Cassandra's key, whatever was put in this repository.

| Key | SHA-256 fingerprint |
|---|---|
| **primary** root | `b8480dd60c5fb3c58a78b96c1adb3e9ecf2f82dc9deae60ed174fbbfa8e5e40b` |
| **backup** root | `d40407cfa327559acd7fbd6d867690417cfd77e36efe423ba99ce04c8181d4ae` |

If the primary key ever has to be replaced, see [ROTATION.md](ROTATION.md) (French): only the backup key can announce it.

## Publishing a module

1. Copy the **[module template](https://github.com/Marplestrange/cassandra-module-modele)** and write your module.
2. Sign it with your publisher key.
3. Open a pull request here: [CONTRIBUER.md](CONTRIBUER.md) walks through each step (French).
4. To become a **verified publisher**: [editeurs/LISEZ-MOI.md](editeurs/LISEZ-MOI.md).

Rules at a glance: a third-party module is named `<publisher>_name`; it declares its source (public repository and commit, rebuilt by CI and compared file by file); it declares what it does in `[permissions]`; and it is refused if its code uses `ctypes`, hides its code, or uses the network or processes without saying so.

## Who carries the project

Cassandra is carried by **La Maison Bohème**, a French non-profit association (loi 1901), which accepts donations ([SOUTIEN.md](SOUTIEN.md)). The code is free software (AGPL-3.0): the best way to help is to write or review a module.

---

## For maintainers

```
python outils/registre.py verifier      archives, code, publishers, revocations, advisories, journal, index, freshness; exit 1 on any defect
python outils/registre.py provenance    rebuilds every archive that declares its source and compares file by file
python outils/registre.py publier --cle root.pem --jours 180   signs the index (next series), writes docs/ and the journal
python outils/registre.py vitrine       rewrites the storefront from the published index (signs nothing)
python outils/fraicheur.py renouveler --cle fraicheur.pem      signs and publishes freshness (scheduled task, daily)
```

The root key is **offline** and never lives in this repository nor in CI. The freshness key, a low-privilege key, signs every day "the index is still the current one": if it leaks, an attacker can only extend the validity of an index the root key has already signed. The full trust model is in [GOUVERNANCE.md](GOUVERNANCE.md).

License: AGPL-3.0.
