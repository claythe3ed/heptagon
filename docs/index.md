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
3. **A signed record cannot be silently modified.** Ed25519 signature
   verification rejects any post-hoc change.

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

## Where to go next

- [Install](getting-started/install.md) — get Heptagon running
- [Quick Start](getting-started/quick-start.md) — first plan, first audit
- [Philosophy](philosophy.md) — the seven-coordinate schema
- [Architecture](architecture.md) — modules and data flow
- [CLI Reference](cli.md) — all five commands
- [Showcase](showcase.md) — a real ransomware scenario
