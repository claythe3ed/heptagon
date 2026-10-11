"""
Tamper test 2 — strip the F6 (effect) coordinate.

Removes effect_artifacts from the subnet-isolation decision,
simulating a responder who logged the action but never recorded
what changed downstream.

Expected: heptagon audit detects an invalid signature AND reports
the missing F6 coordinate.
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
    if rec["type"] == "decision" and "subnet isolation" in rec["data"].get("rationale", ""):
        print(f"Stripping F6 from decision at line {i + 1}")
        rec["data"]["effect_artifacts"] = []
        lines[i] = json.dumps(rec)
        break

LOG.write_text("\n".join(lines) + "\n")
print("F6 stripped. Run:  heptagon audit meridian-incident.jsonl")
