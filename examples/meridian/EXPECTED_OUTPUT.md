# Expected Output

Reference output for each command in this scenario. Use to verify
your run matches the framework's behavior.

Note: UUIDs and signatures differ per run (each run generates a
fresh Ed25519 keypair). Structure, exit codes, and detection
messages are stable.

---

## 1. Declare

    $ heptagon declare meridian-cirp.yaml
    Plan:         meridian_health_cirp (v1.0)
    Teams:        5
    Stakeholders: 4
    Scenarios:    2
    Edges:        4

    Team roles:
      - crisis_mgmt
      - cyber_mgmt
      - product_owner
      - response
      - third_party

    Scenarios:
      - data_breach
      - ransomware

Exit code: 0

---

## 2. Simulate ransomware

    $ heptagon simulate ransomware --plan meridian-cirp.yaml --rounds 30
    Scenario: ransomware
    Rounds:   30
    Valid:    True
    Coverage: 100.00%

    Escalation path:
      response -> cyber_mgmt  (1 hops)
      response -> crisis_mgmt  (2 hops)
      response -> third_party  (3 hops)

Exit code: 0

---

## 3. Log incident

    $ python log_incident.py
    Logged 8 evidence items, 8 decisions
    Written to: meridian-incident.jsonl

Produces a 16-line JSONL file (8 evidence + 8 decisions).

---

## 4. Audit clean log

    $ heptagon audit meridian-incident.jsonl
    Log:       meridian-incident.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 8

    OK: True

Exit code: 0

---

## 5. Tamper - rationale

    $ python tamper_rationale.py
    Tampering with decision at line 14
      Original: Engage Mandiant for forensic scope analysis and PHI assessment.
      Tampered: Routine vendor maintenance call
    Tamper applied. Run:  heptagon audit meridian-incident.jsonl

    $ heptagon audit meridian-incident.jsonl
    Log:       meridian-incident.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 7
    Invalid signatures (1):
      - UUID

    OK: False

Exit code: 1

---

## 6. Tamper - F6 coordinate

    $ python tamper_f6.py
    Stripping F6 from decision at line 11
    F6 stripped. Run:  heptagon audit meridian-incident.jsonl

    $ heptagon audit meridian-incident.jsonl
    Log:       meridian-incident.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 7
    Invalid signatures (1):
      - UUID

    Incomplete 7D records (1):
      - UUID: missing F6

    OK: False

Exit code: 1

---

## 7. Tamper - evidence reference

    $ python tamper_evidence.py
    Corrupting evidence ref at line 9
    Evidence ref corrupted. Run:  heptagon audit meridian-incident.jsonl

    $ heptagon audit meridian-incident.jsonl
    Log:       meridian-incident.jsonl
    Evidence:  8
    Decisions: 8

    Ed25519 valid: 7
    Invalid signatures (1):
      - UUID

    Dangling evidence refs (1):
      - UUID -> ghost-evidence-id-does-not-exist

    OK: False

Exit code: 1

---

## Summary

| Command | Exit code | Detects |
|---|---|---|
| heptagon declare | 0 | Plan valid |
| heptagon simulate | 0 | Escalation reachable |
| python log_incident.py | 0 | Log written |
| heptagon audit (clean) | 0 | All 8 signatures valid |
| heptagon audit (rationale tampered) | 1 | Invalid signature |
| heptagon audit (F6 stripped) | 1 | Invalid signature + missing F6 |
| heptagon audit (ghost ref) | 1 | Invalid signature + dangling ref |
