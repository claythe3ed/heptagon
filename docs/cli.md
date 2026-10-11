# CLI Reference

Heptagon provides five subcommands. Every command supports `--json`
for machine-readable output and uses CI-friendly exit codes:

| Exit code | Meaning |
|---|---|
| `0` | Success — all checks passed |
| `1` | Plan or log fails a compliance check |
| `2` | Invalid input (bad file, unknown scenario, malformed log) |

---

## `heptagon declare <plan.yaml>`

Validate a plan against the JSON Schema and summarize its structure.

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

    Scenarios:
      - data_breach
      - phishing_compromise
      - ransomware

**Options:**

- `--json` — emit the summary as JSON

**Exit codes:**

- `0` — plan valid
- `2` — plan file not found, or schema validation failed

---

## `heptagon verify <plan.yaml>`

Run all six compliance gates and report.

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

**Options:**

- `--json` — emit the full report as JSON

**Exit codes:**

- `0` — all gates passed
- `1` — one or more gates failed
- `2` — plan file not found, or schema validation failed

---

## `heptagon simulate <scenario> --plan <plan.yaml>`

Walk the scenario's escalation order through the reporting DAG.

    $ heptagon simulate ransomware --plan examples/cirp-reference.yaml
    Scenario: ransomware
    Rounds:   20
    Valid:    True
    Coverage: 100.00%

    Escalation path:
      response -> cyber_mgmt  (1 hops)
      response -> crisis_mgmt  (2 hops)

When a hop cannot be reached, it appears in the **Gaps** section:

    Gaps:
      crisis_mgmt -> third_party  (UNREACHABLE)

**Options:**

- `--plan <path>` — required; path to the CIRP plan
- `--rounds N` — simulation rounds (default: 20)
- `--json` — emit the full result as JSON

**Exit codes:**

- `0` — escalation valid, coverage 100%
- `1` — escalation has gaps or mandate violations
- `2` — plan file not found, or unknown scenario

---

## `heptagon keygen --out <path>`

Generate an Ed25519 keypair.

    $ heptagon keygen --out ~/.heptagon/my-key.json
    Keypair written to: ~/.heptagon/my-key.json
    Algorithm:          ed25519
    Public key (hex):   ...64 hex chars...

    Keep the private key secure. Back up the file.
    The public key is safe to share.

**Options:**

- `--out <path>` — required; destination for the keypair JSON
- `--force` — overwrite if the file exists
- `--json` — emit the keypair metadata as JSON

!!! warning "Protect the private key"
    The keypair file is written with `0600` permissions. It is
    **not** encrypted at rest. Anyone who reads this file can forge
    signatures for records you claim to have signed.

---

## `heptagon audit <log.jsonl>`

Verify every signature and every 7D record in an incident log.

    $ heptagon audit incidents.jsonl
    Log:       incidents.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 8

    OK: True

When a signed record was modified after signing:

    $ heptagon audit incidents.jsonl
    Log:       incidents.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 7
    Invalid signatures (1):
      - 79069348-d450-42e9-86f9-cde3e0b43790

    OK: False

**Options:**

- `--json` — emit the full audit report as JSON

**Exit codes:**

- `0` — all signatures valid, all 7D records complete, no dangling refs
- `1` — any of the above failed
- `2` — log file not found or malformed

---

## `heptagon --version`

    $ heptagon --version
    heptagon 1.0.1

## `heptagon --help`

Lists all subcommands and global options.

    $ heptagon --help
    usage: heptagon [-h] [--version] {declare,verify,audit,keygen,simulate} ...

    Seven coordinates. Every incident. Verified.

    positional arguments:
      {declare,verify,audit,keygen,simulate}
        declare             validate a plan against the JSON schema and summarize it
        verify              run all six compliance gates on a plan
        audit               verify signatures + 7D completeness of an incident log
        keygen              generate an Ed25519 keypair for signing decisions
        simulate            run a tabletop exercise for one scenario

    options:
      -h, --help            show this help message and exit
      --version             show program's version number and exit
