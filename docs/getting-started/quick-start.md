# Quick Start

A five-minute tour of Heptagon. By the end you will have generated a
signing keypair, validated a plan, simulated a scenario, and audited
a signed incident log.

## 1. Generate a signing keypair

    heptagon keygen --out ~/.heptagon/my-key.json

Output:

    Keypair written to: ~/.heptagon/my-key.json
    Algorithm:          ed25519
    Public key (hex):   ...64 hex chars...

    Keep the private key secure. Back up the file.
    The public key is safe to share.

!!! warning "Protect the private key"
    The keypair file is written with `0600` permissions (only your
    user can read it). It is **not** encrypted at rest. If someone
    obtains this file, they can forge signatures for records you
    claim to have signed.

## 2. Validate a CIRP plan

A Cyber Incident Response Plan is declared in YAML. Heptagon ships a
reference plan you can use as a starting point:

    heptagon declare examples/cirp-reference.yaml

Output:

    Plan:         reference_cirp (v1.0)
    Teams:        5
    Stakeholders: 3
    Scenarios:    3
    Edges:        4

The `declare` command validates the plan against a JSON Schema before
summarizing it. If any required field is missing or any team role is
invalid, the command exits with code 2 and reports the specific
schema violation.

## 3. Run the six compliance gates

    heptagon verify examples/cirp-reference.yaml

Output:

    Plan:              reference_cirp (v1.0)
    All checks passed: False

      [PASS] teams_complete
      [PASS] reporting_chain
      [PASS] evidence_completeness
      [FAIL] no_hidden_thing
              reason: no evidence logged
      [PASS] break_glass_logged
      [PASS] 7d_completeness

`no_hidden_thing` fails because the plan has no logged incident
records yet. That is expected — a plan with no evidence cannot pass
all six gates. Exit code is `1`.

## 4. Simulate an escalation

    heptagon simulate ransomware --plan examples/cirp-reference.yaml

Output:

    Scenario: ransomware
    Rounds:   20
    Valid:    True
    Coverage: 100.00%

    Escalation path:
      response -> cyber_mgmt  (1 hops)
      response -> crisis_mgmt  (2 hops)

The `simulate` command walks the scenario's escalation order through
the reporting DAG and verifies every hop is reachable. If any role
in the escalation order cannot be reached, it is listed as a gap and
the command exits with code 1.

## 5. Log an incident (library)

The CLI does not log incidents — that is done from Python:

    from heptagon.audit.log import IncidentLog, save_log
    from heptagon.audit.signing import Signer
    from heptagon.cirp.model import Decision, Evidence

    signer = Signer.generate()
    log = IncidentLog()

    ev = Evidence.from_bytes("soc", "analyst", b"alert-001", "initial alert")
    log.append_evidence(ev)

    d = Decision.new(
        actor="cyber_mgmt",
        rationale="isolate host-12",
        evidence_refs=[ev.evidence_id],
        effect_artifacts=[ev.evidence_id],
        predecessor="response",
        successors=["crisis_mgmt"],
        signer=signer,
    )
    log.append_decision(d)
    save_log(log, "incidents.jsonl")

## 6. Audit the log

    heptagon audit incidents.jsonl

Output:

    Log:       incidents.jsonl
    Evidence:  1
    Decisions: 1

    Ed25519 valid: 1

    OK: True

Now modify one byte in `incidents.jsonl` and run the audit again.
Heptagon reports the record ID as having an invalid signature and
exits with code 1.

## Where to go next

- [CLI Reference](../cli.md) — every command and option
- [Philosophy](../philosophy.md) — the seven-coordinate schema
- [Showcase](../showcase.md) — a realistic ransomware scenario
