"""
Tamper test 3 — point an evidence reference at a non-existent record.

Replaces the evidence reference on the initial escalation decision
with a ghost UUID. Simulates a log where the decision references
evidence that was never actually captured.

Expected: heptagon audit detects both the invalid signature and
the dangling evidence reference.
"""
import json
from pathlib import Path

LOG = Path("meridian-incident.jsonl")

if not LOG.exists():
    print(f"ERROR: {LOG} not found. Run log_incident.py first.")
    raise SystemExit(1)

lines = LOG.read_text().splitlines()
for i, line in enumerate(lines):
    rec = json.loads(line)
    if rec["type"] == "decision" and "mass encryption" in rec["data"].get("rationale", ""):
        print(f"Corrupting evidence ref at line {i + 1}")
        rec["data"]["evidence_refs"] = ["ghost-evidence-id-does-not-exist"]
        lines[i] = json.dumps(rec)
        break

LOG.write_text("\n".join(lines) + "\n")
print("Evidence ref corrupted. Run:  heptagon audit meridian-incident.jsonl")
