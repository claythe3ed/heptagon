# MediNet S3 Leak — Real Dataset from CSIRT-Sim

A second showcase for Heptagon, built on **real scenario data from an
external open-source project**.

Unlike the Meridian example (which was authored for this repo), this
example demonstrates Heptagon working with data produced by a
different tool.

## Data source

**[CSIRT-Sim](https://github.com/U55-BK/csirt)** — an open-source
crisis simulation project for training multi-disciplinary incident
response teams.

- License: **AGPL-3.0**
- **The scenario JSON is not bundled with Heptagon.** It stays in
  the CSIRT-Sim repository. This example only ships the converter.
- If you use CSIRT-Sim's data, follow their license terms.

## The scenario

**`s3-leak-medinet-v1`** — a fictional Polish healthcare network
(MediNet, 40 clinics, 520,000 patients) discovers that an AWS S3
bucket containing patient medical records has been publicly
accessible for six weeks due to a junior DevOps misconfiguration
during a cloud migration.

- 5,000 patient records exposed: PESEL, addresses, diagnoses,
  prescriptions, lab results (GDPR Article 9 special category)
- A journalist from Niebezpiecznik.pl already has samples
- Regulatory deadlines apply: UODO (72h), NIS2, Polish health law
- No attacker to negotiate with — the incident is entirely
  self-inflicted
- Roles involved: board, CISO, legal
- Golden path: 25 steps compressed into 24 game-hours

## Why this example matters

The Meridian example was written for this repo. The MediNet example
proves Heptagon can consume **real scenario data from a separate
project** without modification to the core framework.

It also stresses a different incident class:
- **No active attacker** — pure consequence management
- **GDPR Article 9** — special category data (health)
- **Self-inflicted** — accountability is the central question
- **36 possible actions across 3 roles**, only 25 on the golden path

## How to run it

### 1. Clone the data source

    git clone https://github.com/U55-BK/csirt.git ~/datasets/csirt

### 2. Generate the signed log

    cd ~/datasets/csirt
    python /path/to/heptagon/examples/medinet/convert_to_heptagon.py

Produces:
- `/tmp/medinet-s3-leak.jsonl` — signed incident log
- `/tmp/medinet-ir-key.json` — Ed25519 keypair used to sign

### 3. Audit, seal, audit again

    heptagon audit /tmp/medinet-s3-leak.jsonl
    heptagon seal  /tmp/medinet-s3-leak.jsonl --sign-with /tmp/medinet-ir-key.json
    heptagon audit /tmp/medinet-s3-leak.jsonl

Expected: 25 decisions, 15 evidence items, all signatures valid,
seal verified.

### 4. Run the tamper tests

    cd /tmp
    bash /path/to/heptagon/examples/medinet/tamper_tests.sh

Expected: three attacks, three detections, exit codes 1, 1, 1.

## Files

| File | Purpose |
|---|---|
| `convert_to_heptagon.py` | Reads CSIRT-Sim JSON, writes Heptagon JSONL |
| `tamper_tests.sh` | Deletes, modifies, and reorders records to prove detection |
| `EXPECTED_OUTPUT.md` | Reference output for every command |
| `.gitignore` | Excludes generated logs and keys from version control |

## What Heptagon detects on this data

| Attack | Detected by |
|---|---|
| Delete a decision from the log | Merkle root mismatch |
| Modify a signed decision | Ed25519 signature invalid |
| Reorder two decisions in the log | Merkle root mismatch |

Attacks 1 and 3 are the interesting ones. Ed25519 alone would report
`OK: True` on a log where a decision was deleted or two decisions were
swapped. The Merkle seal catches both — provided the `.root` file is
anchored outside the audit machine. See
[`docs/threat-model.md`](https://claythe3ed.github.io/heptagon/threat-model/).

## Attribution

Scenario data: CSIRT-Sim contributors.
Converter: Heptagon (MIT).
The two projects are independent. No code or data is shared between
them beyond the JSONL output that the converter produces.
