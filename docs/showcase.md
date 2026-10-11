# Showcase — Meridian Health Ransomware Scenario

A realistic incident-response scenario demonstrating Heptagon
end-to-end. Fictional hospital network. Fictional attack. Real
framework behavior.

The full scenario lives in
[`examples/meridian/`](https://github.com/claythe3ed/heptagon/tree/main/examples/meridian)
in the repository. This page walks through what it shows.

---

## The scenario

Meridian Health Systems, a mid-size hospital network, is hit by
ransomware on a Friday evening. Over the next ~10 hours an incident
unfolds:

- Initial detection
- Containment
- Clinical downtime procedures
- Backup recovery via break-glass
- Third-party forensics engagement
- Confirmation that ~48,000 patient records were exfiltrated
- HIPAA notification clock starts

Every decision during that response is logged with all seven
coordinates.

---

## What it demonstrates

| Step | Command | What it proves |
|---|---|---|
| 1 | `heptagon declare meridian-cirp.yaml` | The plan validates against the JSON Schema |
| 2 | `heptagon simulate ransomware --plan ...` | The escalation order is reachable through the reporting DAG |
| 3 | `python log_incident.py` | 8 evidence items + 8 signed decisions |
| 4 | `heptagon audit meridian-incident.jsonl` | All 8 signatures valid |
| 5 | `python tamper_rationale.py` | Audit detects the invalidated signature |
| 6 | `python tamper_f6.py` | Audit detects the missing F6 coordinate |
| 7 | `python tamper_evidence.py` | Audit detects the dangling evidence reference |

---

## The three tamper attacks

Each script performs **one specific attack**. After running it,
`heptagon audit` reports the failure.

### Attack 1 — modify a signed rationale

An attacker rewrites the rationale of the decision that engaged
Mandiant, making it look like a routine vendor call rather than the
forensic investigation that uncovered PHI exfiltration.

**Detection:** the Ed25519 signature no longer verifies.

    Ed25519 valid: 7
    Invalid signatures (1):
      - <uuid>

    OK: False

### Attack 2 — strip the F6 coordinate

An attacker (or a careless responder) removes `effect_artifacts`
from the subnet-isolation decision, hiding what changed downstream.

**Detection:** invalid signature **and** a missing F6 coordinate.

    Ed25519 valid: 7
    Invalid signatures (1):
      - <uuid>

    Incomplete 7D records (1):
      - <uuid>: missing F6

    OK: False

### Attack 3 — point at non-existent evidence

An attacker replaces an evidence reference with a UUID that does not
exist in the log, hiding which artifact actually justified a decision.

**Detection:** invalid signature **and** a dangling evidence ref.

    Ed25519 valid: 7
    Invalid signatures (1):
      - <uuid>

    Dangling evidence refs (1):
      - <uuid> -> ghost-evidence-id-does-not-exist

    OK: False

---

## Why the double coverage matters

Attacks 2 and 3 are caught **twice**:

1. **Cryptographic layer** — signature verification catches the fact
   that *something* in the record changed.
2. **Semantic layer** — the 7D gate reports *what specifically* is
   missing.

This is deliberate. There is no single point of failure. An attacker
would need to both forge the signature (impossible without the
private key) and fill in the missing fields consistently.

---

## Run it yourself

    git clone https://github.com/claythe3ed/heptagon.git
    cd heptagon/examples/meridian

    heptagon declare meridian-cirp.yaml
    heptagon simulate ransomware --plan meridian-cirp.yaml --rounds 30

    python log_incident.py
    heptagon audit meridian-incident.jsonl

    python tamper_rationale.py
    heptagon audit meridian-incident.jsonl

    python tamper_f6.py
    heptagon audit meridian-incident.jsonl

    python tamper_evidence.py
    heptagon audit meridian-incident.jsonl

Every run generates a fresh Ed25519 keypair, so UUIDs and signatures
differ per run. Structure, exit codes, and detection messages are
stable.

Reference output is documented in
[`examples/meridian/EXPECTED_OUTPUT.md`](https://github.com/claythe3ed/heptagon/blob/main/examples/meridian/EXPECTED_OUTPUT.md).

---

## What the scenario demonstrates about the framework

- **Real-world scale.** 8 evidence items, 8 decisions, 10 hours of
  incident response, HIPAA pressure, third-party engagement.
- **Tamper detection works.** Three attack classes, all caught.
- **The gates compose.** Passing all six requires evidence + signed
  decisions + populated coordinates. Failing any one names the gap.
- **The framework assumes honest actors.** Attack 1 required
  modifying the log file. Attacks 2 and 3 required modifying signed
  fields. The framework catches all three — but a compromised
  signing key is outside its threat model.

See the [Threat Model](threat-model.md) for what is and is not
in scope.
