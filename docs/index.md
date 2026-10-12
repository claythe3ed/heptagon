# Heptagon

**Seven coordinates. Every incident. Verified.**

A symbolic, formal, and executable framework for cybersecurity
incident response planning and management.

---

## What it does

Heptagon treats every incident record as a **seven-coordinate object**.
A record missing its intention, its effect, or its lineage position is
not complete — and an incomplete record cannot be certified as
truthful.

The framework makes three claims falsifiable:

1. **A complete plan has no gaps.** Every escalation path in every
   scenario must be reachable through the reporting chain.
2. **A complete record populates all seven coordinates.** No silent
   omissions.
3. **A signed record cannot be silently modified, deleted, reordered,
   or truncated.** Ed25519 signatures catch modification of individual
   records. A Merkle seal over the log catches deletion, reordering,
   and truncation — the shape of the file itself.

Each claim is enforced by a specific compliance gate. Each gate can
fail. Each failure names the specific record and the specific
coordinate or field.

---

## Install

    pip install heptagon7

The PyPI project is named `heptagon7` because `heptagon` was taken.
After installation, both the Python import and the CLI command are
`heptagon`.

---

## Quick example

    # Generate a signing keypair
    heptagon keygen --out ~/.heptagon/my-key.json

    # Validate a CIRP plan
    heptagon declare examples/cirp-reference.yaml

    # Run the six compliance gates
    heptagon verify examples/cirp-reference.yaml

    # Simulate a scenario
    heptagon simulate ransomware --plan examples/cirp-reference.yaml

    # Audit an incident log for tampering
    heptagon audit incidents.jsonl

    # Seal the log with a Merkle root (v1.1.0)
    heptagon seal incidents.jsonl

---

## The six compliance gates

| # | Gate | Enforces |
|---|---|---|
| 1 | `check_teams_complete` | All 5 R-C-C-P-T roles present and complete |
| 2 | `check_reporting_chain` | Every reporter can reach an executive |
| 3 | `check_evidence_completeness` | Unique hashes, chronology, valid refs |
| 4 | `check_no_hidden_thing` | Every source reconciles; every decision signed |
| 5 | `check_break_glass_logged` | Emergency overrides are marked AND evidenced |
| 6 | `check_7d_completeness` | Every record populates all seven coordinates |

---

## What the framework detects

| Attack | Detected by |
|---|---|
| Modify a signed record | Ed25519 signature verification |
| Delete a record from a log | Merkle root mismatch |
| Reorder records in a log | Merkle root mismatch |
| Truncate a log at any point | Merkle root mismatch |

The Merkle seal only provides deletion, reordering, and truncation
detection when the root is anchored somewhere the attacker cannot
reach. A seal stored next to the log is a convenience for detecting
accidental corruption, not a security control. `heptagon seal` prints
this note on every run.

See [Threat Model](threat-model.md) for the full boundary.

---

## Where to go next

- [Install](getting-started/install.md) — get Heptagon running
- [Quick Start](getting-started/quick-start.md) — first plan, first audit
- [Philosophy](philosophy.md) — the seven-coordinate schema
- [Architecture](architecture.md) — modules and data flow
- [Threat Model](threat-model.md) — what it protects against, and what it doesn't
- [CLI Reference](cli.md) — all six commands
- [API Reference](api.md) — Python API
- [Showcase](showcase.md) — a real ransomware scenario
