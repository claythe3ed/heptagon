cd ~/projects/heptagon && cat > examples/meridian/README.md << 'MDEOF'
# Meridian Health Systems — Ransomware Scenario

A realistic incident-response scenario used to demonstrate Heptagon
end-to-end. Fictional hospital network. Fictional attack. Real
framework behavior.

## What this demonstrates

1. Plan declaration — a CIRP with 5 teams, 4 stakeholders,
   2 scenarios, written in YAML and validated against the JSON schema.
2. Escalation simulation — walk the ransomware scenario's
   escalation order through the reporting DAG.
3. Signed incident logging — 8 evidence items and 8 decisions,
   every decision populated with all seven coordinates and signed
   with Ed25519.
4. Tamper detection — three attack scenarios, each detected
   and named by heptagon audit.

## The scenario

Meridian Health Systems, a mid-size hospital network, is hit by
ransomware on a Friday evening. Over the next ~10 hours, an incident
unfolds: initial detection, containment, clinical downtime, backup
recovery, third-party forensics, and confirmation that ~48,000
patient records were exfiltrated.

Every decision made during that response is logged with all seven
coordinates:

| Coordinate | Value |
|---|---|
| B (spacetime) | timestamp + actor role |
| F5 (intention) | decision rationale |
| F6 (effect) | evidence IDs of downstream changes |
| F7 (lineage) | predecessor + successors |

## Files

| File | Purpose |
|---|---|
| meridian-cirp.yaml | The CIRP - teams, stakeholders, scenarios, reporting chain |
| log_incident.py | Builds the signed incident log (fresh keypair each run) |
| meridian-ir-key.public.json | Public key from the demo run (for reference) |
| tamper_rationale.py | Attack: rewrite a signed rationale |
| tamper_f6.py | Attack: strip the F6 (effect) coordinate |
| tamper_evidence.py | Attack: point an evidence ref at a nonexistent UUID |
| EXPECTED_OUTPUT.md | What each command prints, for verification |

## Quick start

    cd examples/meridian

    # 1. Declare the plan
    heptagon declare meridian-cirp.yaml

    # 2. Simulate the ransomware scenario
    heptagon simulate ransomware --plan meridian-cirp.yaml --rounds 30

    # 3. Log the incident (generates a fresh signed log)
    python log_incident.py

    # 4. Audit the clean log - should pass
    heptagon audit meridian-incident.jsonl

    # 5. Run any tamper script, then re-audit
    python tamper_rationale.py
    heptagon audit meridian-incident.jsonl

## What the tamper tests prove

Each tamper script performs one specific attack. After running it,
heptagon audit meridian-incident.jsonl reports:

| Attack | Detection |
|---|---|
| tamper_rationale.py | Invalid signatures (1) - signature no longer verifies |
| tamper_f6.py | Invalid signatures (1) + Incomplete 7D records (1): missing F6 |
| tamper_evidence.py | Invalid signatures (1) + Dangling evidence refs (1) |

The double-coverage in tests 2 and 3 is intentional: the framework
catches each attack twice - once at the cryptographic layer
(signature broken) and once at the semantic layer (specific
coordinate or reference missing). No single point of failure.

## Why this scenario

Healthcare is a common ransomware target. The regulatory pressure
(HIPAA notification windows), the mix of technical and business
decisions, and the involvement of third parties make it a realistic
stress test for the framework.

Everything in this scenario is fictional. No real patient data.
No real hospital. No real vendor.

## Regenerating

Every run of log_incident.py generates a fresh Ed25519 keypair
and re-signs all 16 records. Timestamps will differ, so the
specific UUIDs and signatures differ per run - but the structure
and detection behavior are identical.

The .gitignore excludes the generated meridian-incident.jsonl
so no log is committed. The demonstration is the process, not
the artifacts.
MDEOF
echo "DONE: README.md written"
wc -l examples/meridian/README.md
grep -c "^## " examples/meridian/README.md
tail -3 examples/meridian/README.md
