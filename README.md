# Heptagon

![PyPI version](https://img.shields.io/pypi/v/heptagon7)
![Python versions](https://img.shields.io/pypi/pyversions/heptagon7)
![License](https://img.shields.io/github/license/claythe3ed/heptagon)
![Status](https://img.shields.io/badge/status-v1.0.0-brightgreen)
![Tests](https://img.shields.io/badge/tests-102%20passing-brightgreen)
![Dependencies](https://img.shields.io/badge/deps-numpy%20%7C%20PyYAML%20%7C%20jsonschema%20%7C%20PyNaCl-blue)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)

> **Seven coordinates. Every incident. Verified.**

Heptagon is a symbolic, formal, and executable framework for
cybersecurity incident response planning and management. It treats
every incident record as a seven-coordinate object — and refuses to
certify any record that fails to populate all seven.

---

## Table of Contents

- [Why Heptagon](#why-heptagon)
- [Install](#install)
- [Quick Start (CLI)](#quick-start-cli)
- [Quick Start (Library)](#quick-start-library)
- [The Seven Coordinates](#the-seven-coordinates)
- [The Six Compliance Gates](#the-six-compliance-gates)
- [CLI Reference](#cli-reference)
- [Incident Log Format](#incident-log-format)
- [Plan Declaration Format](#plan-declaration-format)
- [Architecture](#architecture)
- [Testing](#testing)
- [Design Principles](#design-principles)
- [Honest Limits](#honest-limits)
- [Contributing](#contributing)
- [Citation](#citation)
- [License](#license)

---

## Why Heptagon

Incident response today is documented in prose. Plans live in PDFs.
Logs live in ticketing systems. There is no formal way to answer the
question: **"Is this incident record complete?"**

Heptagon answers that question by treating a record as a
seven-coordinate object. A record missing its intention, its effect,
or its lineage position is *not* complete — and an incomplete record
cannot be certified as truthful.

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

```bash
pip install heptagon7
```

> **Note on naming.** The PyPI project is `heptagon7` because
> `heptagon` was already taken. After installation, both the Python
> import and the CLI command are `heptagon`:

```python
import heptagon          # library
```

```bash
heptagon --help          # CLI
```

For local development:

```bash
git clone https://github.com/claythe3ed/heptagon.git
cd heptagon
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Quick Start (CLI)

```bash
# 1. Generate an Ed25519 keypair for signing decisions
heptagon keygen --out ~/.heptagon/my-key.json

# 2. Validate a CIRP plan against the JSON schema
heptagon declare examples/cirp-reference.yaml

# 3. Run the six compliance gates on the plan
heptagon verify examples/cirp-reference.yaml

# 4. Simulate a scenario's escalation
heptagon simulate ransomware --plan examples/cirp-reference.yaml

# 5. Audit an incident log for signature and 7D validity
heptagon audit incidents.jsonl
```

Every command supports `--json` for machine-readable output and uses
CI-friendly exit codes:

| Exit code | Meaning |
|---|---|
| `0` | Success — all checks passed |
| `1` | Plan or log fails a compliance check |
| `2` | Invalid input (bad file, unknown scenario, malformed log) |

---

## Quick Start (Library)

```python
from heptagon.audit.log import IncidentLog, save_log
from heptagon.audit.signing import Signer
from heptagon.cirp.model import Decision, Evidence

# Create a keypair
signer = Signer.generate()

# Log evidence
log = IncidentLog()
ev = Evidence.from_bytes("soc", "analyst", b"alert-payload", "initial alert")
log.append_evidence(ev)

# Log a signed decision populating all seven coordinates
d = Decision.new(
    actor="cyber_mgmt",
    rationale="isolate host-12 from network",
    evidence_refs=[ev.evidence_id],
    effect_artifacts=[ev.evidence_id],   # F6
    predecessor="response",               # F7
    successors=["crisis_mgmt"],           # F7
    signer=signer,
)
log.append_decision(d)

# Persist
save_log(log, "incidents.jsonl")
```

Any change to `d.rationale`, `d.evidence_refs`, or any other signed
field invalidates the signature. The `heptagon audit` command
detects it and names the record.

---

## The Seven Coordinates

An incident record lives in the fiber bundle `E = B × F5 × F6 × F7`.

| Coordinate | Name | Captured by |
|---|---|---|
| **B0–B3** | Spacetime | `timestamp`, `actor`, `source` |
| **F5** | Intention | `Decision.rationale` |
| **F6** | Effect | `Decision.effect_artifacts` |
| **F7** | Lineage | `Decision.predecessor` + `successors` |

A record that omits any coordinate is **partial**. A partial record is
not a truthful record.

See [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md) for the full derivation.

---

## The Six Compliance Gates

`CIRPModel.verify_all()` runs all six gates and returns a consolidated
report. Every gate can fail.

| # | Gate | Enforces |
|---|---|---|
| 1 | `check_teams_complete` | All 5 R-C-C-P-T roles present and complete |
| 2 | `check_reporting_chain` | Every reporter can reach an executive role |
| 3 | `check_evidence_completeness` | Unique hashes, chronological order, valid references |
| 4 | `check_no_hidden_thing` | Every source slice reconciles; every decision verifiably signed |
| 5 | `check_break_glass_logged` | Every emergency override is marked AND evidenced |
| 6 | `check_7d_completeness` | Every record populates all seven coordinates |

The gates are composable. Passing all six does not guarantee a plan
is correct — but failing any one of them guarantees it is incomplete.

---

## CLI Reference

### `heptagon declare <plan.yaml>`

Validate a plan against the JSON schema and summarize its structure.

```
$ heptagon declare examples/cirp-reference.yaml
Plan:         reference_cirp (v1.0)
Teams:        5
Stakeholders: 3
Scenarios:    3
Edges:        4

Team roles:
  - crisis_mgmt
  - cyber_mgmt
  - product_owner
  - response
  - third_party
...
```

### `heptagon verify <plan.yaml>`

Run the six compliance gates. Exit code 0 if all pass.

```
$ heptagon verify examples/cirp-reference.yaml
Plan:              reference_cirp (v1.0)
All checks passed: False

  [PASS] teams_complete
  [PASS] reporting_chain
  [PASS] evidence_completeness
  [FAIL] no_hidden_thing
          reason: no evidence logged
  [PASS] break_glass_logged
  [PASS] 7d_completeness
```

### `heptagon simulate <scenario> --plan <plan.yaml>`

Walk a scenario's escalation order through the reporting DAG. Report
coverage, gaps, and mandate violations.

```
$ heptagon simulate ransomware --plan examples/cirp-reference.yaml
Scenario: ransomware
Rounds:   20
Valid:    True
Coverage: 100.00%

Escalation path:
  response -> cyber_mgmt  (1 hops)
  response -> crisis_mgmt  (2 hops)
```

### `heptagon keygen --out <path>`

Generate an Ed25519 keypair. The private key is written with `0600`
permissions.

```
$ heptagon keygen --out ~/.heptagon/my-key.json
Keypair written to: ~/.heptagon/my-key.json
Algorithm:          ed25519
Public key (hex):   ...64 hex chars...

Keep the private key secure. Back up the file.
The public key is safe to share.
```

### `heptagon audit <log.jsonl>`

Verify every signature and every 7D record in an incident log.

```
$ heptagon audit incidents.jsonl
Log:       incidents.jsonl
Evidence:  2
Decisions: 2

Ed25519 valid: 2

OK: True
```

If a signed record was modified after signing:

```
$ heptagon audit incidents.jsonl
Log:       incidents.jsonl
Evidence:  2
Decisions: 2

Ed25519 valid: 1
Invalid signatures (1):
  - 79069348-d450-42e9-86f9-cde3e0b43790

OK: False
```

---

## Incident Log Format

An incident log is a **JSONL** file. Each line is a self-contained
JSON record.

```json
{"type": "evidence", "data": {...}}
{"type": "decision", "data": {...}}
```

Records are ordered. Append-only semantics are recommended — never
rewrite a log once written, only append to it.

**Why JSONL:**
- Append-only (perfect for incident logging)
- Line-level recovery (one corrupt line doesn't destroy the file)
- Standard format for forensic logs
- Diff-friendly in version control

---

## Plan Declaration Format

CIRPs are declared in YAML and validated against
[`schemas/cirp.schema.json`](schemas/cirp.schema.json).

```yaml
name: reference_cirp
version: "1.0"

teams:
  - role: response
    members: [IR lead, SOC analyst 1, forensics eng]
    contact: "+1-555-0101"
    backup: "+1-555-0102"
    mandate: "Fix the breach, rebuild systems, execute recovery."
  # ... 4 more teams ...

reporting_chain:
  - [response, cyber_mgmt]
  - [cyber_mgmt, crisis_mgmt]
  - [third_party, cyber_mgmt]

scenarios:
  - name: ransomware
    triggers: [mass file rename, ransom note]
    escalation: [response, cyber_mgmt, crisis_mgmt]
    key_considerations: [backup integrity, isolate segments]
```

Full example: [`examples/cirp-reference.yaml`](examples/cirp-reference.yaml).

---

## Architecture

```
heptagon/
├── core/symbolic.py         Symbolic layer
│   ├── FiberBundle7D        7D record space
│   ├── MoralSheaf           flabbiness / injective recording
│   ├── Lineage              DAG of reporting structure
│   ├── PresentationOperator who sees what
│   ├── TestimonyOperator    per-component attestation
│   ├── MoralJacobians       responsibility vs. influence
│   └── UnifiedEvaluation    faithfulness metrics
├── cirp/
│   ├── model.py             CIRP primitives + six gates
│   └── yaml_loader.py       plan loading + schema validation
├── audit/
│   ├── signing.py           Ed25519 signing
│   └── log.py               JSONL incident-log reader/writer
├── cli/main.py              argparse-based CLI
└── simulation/
    ├── internal_simulator.py numpy-only agent simulator
    └── stuxnet_test.py       historical validation
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full
module map, data flow, and gate definitions.

---

## Testing

```bash
pytest tests/ -v
```

| Suite | Tests | Covers |
|---|---|---|
| `test_symbolic.py` | 26 | Symbolic core: bundle, sheaf, lineage, operators |
| `test_cirp_checks.py` | 25 | Six compliance gates, tabletop validation |
| `test_signing.py` | 14 | Ed25519 lifecycle, tamper detection |
| `test_log_and_audit.py` | 11 | JSONL round-trip, CLI audit behavior |
| `test_cli.py` | 10 | CLI commands, exit codes, JSON output |
| `test_yaml_loader.py` | 9 | Schema validation, round-trip compilation |
| `test_simulation.py` | 7 | Deterministic agent simulator |
| **Total** | **102** | |

Every gate has at least one test that proves it can **fail**, not just
pass. A check that cannot fail is not a check.

---

## Design Principles

1. **Falsifiable claims.** Every feature can be tested. If a claim
   cannot be tested, it does not belong in this codebase.

2. **Honest limits.** The threat model states what the framework
   protects against, and — critically — what it does not.

3. **Standard cryptography.** Ed25519 via PyNaCl. No custom crypto,
   no roll-your-own primitives.

4. **Minimal dependencies.** `numpy`, `PyYAML`, `jsonschema`,
   `PyNaCl`. Nothing else.

5. **Python 3.11+.** Modern typing syntax, no legacy compatibility
   burden.

---

## Honest Limits

**What Heptagon protects against:**

- Accidental omission of evidence or decisions
- Post-hoc modification of a signed record
- Unreachable escalation paths in a plan
- Plans missing required teams or reporting edges

**What Heptagon does NOT protect against:**

- A compromised signing key — if the attacker has the private key,
  they can forge signatures
- A malicious insider with write access to the audit log — they can
  delete records
- A determined attacker with control of the audit machine
- Legal admissibility disputes — cryptography is valid; admissibility
  depends on jurisdiction
- Real-time detection — Heptagon reads logs after the fact
- Threat intelligence — Heptagon does not track adversaries

Full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Contributing

Issues and pull requests are welcome at
[github.com/claythe3ed/heptagon](https://github.com/claythe3ed/heptagon).

Guidelines:

- Every feature must have a test that proves it can fail.
- Every claim in the README must be backed by code.
- No new dependencies without discussion.

---

## Citation

If you use Heptagon in research or security work, please cite:

```bibtex
@software{heptagon2026,
  author = {Muhammad Ali},
  title  = {Heptagon: Seven coordinates. Every incident. Verified.},
  year   = {2026},
  url    = {https://github.com/claythe3ed/heptagon},
  note   = {PyPI: heptagon7}
}
```

---

## License

MIT. See [LICENSE](LICENSE).
```

---

## What Changed

| Section | Before | After |
|---|---|---|
| **Badges** | None | 7 badges (PyPI, Python, license, status, tests, deps, Python version) |
| **Table of Contents** | None | Full 14-section ToC |
| **Why Heptagon** | None | Problem statement + three falsifiable claims |
| **Quick Start** | Just demo commands | Split CLI + Library paths, real examples with output |
| **CLI Reference** | None | All 5 commands documented with example output |
| **Incident Log Format** | None | JSONL spec + rationale |
| **Plan Declaration Format** | None | YAML schema snippet |
| **Architecture** | 5 lines | Full tree with descriptions |
| **Testing** | "102 tests" in status | Breakdown table by file |
| **Design Principles** | None | 5 explicit principles |
| **Honest Limits** | "Not production-ready before v1.0" | Split into protects/does-not-protect, updated for real Ed25519 |
| **Citation** | None | BibTeX entry |
| **Status** | "v0.1.0 — 58 tests" | Removed (badges cover this) |

---

## How to Apply

```bash
cd ~/projects/heptagon
source .venv/bin/activate

# Backup current README
cp README.md README.md.bak

# Then paste the new README content into a fresh file
nano README.md
```

o `nano README.md`, save, then run the commit + push commands. Paste the output.**
