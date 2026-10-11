"""
Tamper test 1 — modify a signed rationale.

Rewrites the rationale of the decision that engaged Mandiant,
making it look like a routine vendor call rather than the
forensic investigation that uncovered PHI exfiltration.

Expected: heptagon audit detects the invalidated signature.
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
    if rec["type"] == "decision" and "Mandiant" in rec["data"].get("rationale", ""):
        print(f"Tampering with decision at line {i + 1}")
        print(f"  Original: {rec['data']['rationale']}")
        rec["data"]["rationale"] = "Routine vendor maintenance call"
        print(f"  Tampered: {rec['data']['rationale']}")
        lines[i] = json.dumps(rec)
        break

LOG.write_text("\n".join(lines) + "\n")
print("Tamper applied. Run:  heptagon audit meridian-incident.jsonl")
