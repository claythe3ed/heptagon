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

## `heptagon seal <log.jsonl>`

Compute a SHA-256 Merkle root over every record in a JSONL incident
log. Write a companion `<log>.jsonl.root` file containing the root
and a record count.

    $ heptagon seal meridian-incident.jsonl
    Seal written to: meridian-incident.jsonl.root
    Log:             meridian-incident.jsonl
    Records sealed:  16
    Merkle root:     54ef31e0846679f5...

    CUSTODY NOTE
      The seal was written next to the log file. If an attacker
      can delete or modify the log, they can delete or modify the
      seal too. On its own, this seal detects accidental
      corruption, not a determined attacker.

      For deletion and reordering detection to hold, copy the
      .root file somewhere outside this machine:
        - A separate Git repository
        - A timestamping service (OpenTimestamps or similar)
        - Write-once storage (WORM filesystem)
        - An email sent to an independent address

      See docs/threat-model.md for the full boundary.

The **custody note is printed to stderr on every run**. It is not
suppressed by `--json`. This is deliberate: a seal stored next to
the log is not a security control, and the command says so.

**Options:**

- `--out <path>` — where to write the seal (default: `<log>.root`)
- `--sign-with <key.json>` — sign the seal with an Ed25519 key
- `--no-note` — suppress the custody note on stderr
- `--json` — emit the seal metadata as JSON to stdout

**Exit codes:**

- `0` — seal written
- `2` — log file not found, or key file could not be loaded

**What the seal detects:**

| Attack                             | Detected? |
|------------------------------------|-----------|
| Delete a record from the log       | Yes       |
| Reorder records in the log         | Yes       |
| Truncate the log at any point      | Yes       |
| Modify one character in a record   | Yes       |
| Delete the log *and* the seal file | No (custody) |

The last row is the boundary. If the attacker can reach both files,
the seal provides no protection. See `docs/threat-model.md`.

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

If a `heptagon seal` companion file is present next to the log,
`audit` verifies the Merkle root as well:

    $ heptagon audit meridian-incident.jsonl
    Log:       meridian-incident.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 8

    Seal:      VERIFIED (sha256-merkle)

    OK: True

When a record has been deleted from the log, the root no longer
matches and the audit fails:

    Seal:      MISMATCH
      expected root: 54ef31e0846679f5...
      computed root: dc77f919dfb6ad78...
      expected count: 16
      actual count:   15

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
