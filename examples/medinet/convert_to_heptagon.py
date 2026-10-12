"""
convert_to_heptagon.py
======================

Convert a CSIRT-Sim scenario into a signed Heptagon incident log.

Data source
-----------
CSIRT-Sim — an open-source crisis simulation project.
https://github.com/U55-BK/csirt
Licensed AGPL-3.0. Not bundled with Heptagon.

This script is Heptagon's own code (MIT). It reads the scenario
JSON emitted by CSIRT-Sim and produces a Heptagon incident log.
No AGPL content is copied into this repository.

Usage
-----
    git clone https://github.com/U55-BK/csirt.git ~/datasets/csirt
    cd ~/datasets/csirt
    python /path/to/convert_to_heptagon.py

Output
------
    /tmp/medinet-s3-leak.jsonl       — signed incident log
    /tmp/medinet-ir-key.json         — Ed25519 keypair used to sign

Then:
    heptagon audit /tmp/medinet-s3-leak.jsonl
    heptagon seal  /tmp/medinet-s3-leak.jsonl --sign-with /tmp/medinet-ir-key.json
    heptagon audit /tmp/medinet-s3-leak.jsonl

Mapping
-------
    CSIRT-Sim event  ->  Heptagon Evidence
    CSIRT-Sim action ->  Heptagon Decision
    Golden path      ->  the played sequence
    Deadlines        ->  F7 lineage context in the rationale
"""
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Adjust this path if Heptagon lives elsewhere
sys.path.insert(0, str(Path.home() / "projects" / "heptagon"))

from heptagon.audit.log import IncidentLog, save_log
from heptagon.audit.signing import Signer
from heptagon.cirp.model import Decision, Evidence


SCENARIO = Path("scenarios/s3-leak-medinet-v1.json")
OUT_LOG = Path("/tmp/medinet-s3-leak.jsonl")
OUT_KEY = Path("/tmp/medinet-ir-key.json")


def parse_t_plus(step_str):
    """Extract minutes and action id from 'T+10: action-id (note)'."""
    m = re.match(r"T\+(\d+):\s*([a-z0-9-]+)", step_str)
    if not m:
        return None, None
    return int(m.group(1)), m.group(2)


def build_action_index(scenario):
    """Map both 'role.action-id' and 'action-id' to the full action."""
    index = {}
    for role, actions in scenario["actionCatalog"].items():
        for a in actions:
            index[a["id"]] = (role, a)
            short = a["id"].split(".", 1)[1] if "." in a["id"] else a["id"]
            index[short] = (role, a)
    return index


def main():
    scenario = json.loads(SCENARIO.read_text(encoding="utf-8"))
    action_index = build_action_index(scenario)

    # Use today's date at 09:00 UTC as the scenario base time
    base = datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc)

    signer = Signer.generate()
    signer.save(OUT_KEY)
    print(f"Keypair written to: {OUT_KEY}")
    print(f"Public key: {signer.public_key_hex[:16]}...")

    log = IncidentLog()

    # 1. Log hook events as Evidence at T+0
    for ev in scenario["hook"]["events"]:
        e = Evidence.from_bytes(
            source=ev.get("source", "unknown"),
            custodian=", ".join(ev.get("visibleTo", [])),
            data=json.dumps(ev, ensure_ascii=False).encode("utf-8"),
            description=f"{ev['type']}: {ev['title'][:80]}",
        )
        e.timestamp = base
        log.append_evidence(e)
    print(f"Logged {len(scenario['hook']['events'])} hook events")

    # 2. Collect golden-path steps
    all_steps = []
    for role, steps in scenario["goldenPath"]["stepsByRole"].items():
        for s in steps:
            minutes, action_id = parse_t_plus(s)
            if minutes is None:
                continue
            all_steps.append((minutes, role, action_id, s))
    all_steps.sort(key=lambda x: x[0])
    print(f"Golden path has {len(all_steps)} steps")

    # 3. Walk the path, logging signed decisions
    prev_decision_id = None
    for i, (minutes, role, action_id, raw) in enumerate(all_steps):
        if action_id not in action_index:
            continue
        full_role, action = action_index[action_id]
        ts = base + timedelta(minutes=minutes)

        next_roles = []
        for j in range(i + 1, min(i + 3, len(all_steps))):
            next_role = all_steps[j][1]
            if next_role != role and next_role not in next_roles:
                next_roles.append(next_role)

        rationale = action.get("rationale", action.get("description", ""))[:500]
        summary = action.get("summary", "")[:300]

        d = Decision.new(
            actor=full_role,
            rationale=f"[{action['label']}] {summary or rationale}",
            evidence_refs=[log.evidence[0].evidence_id] if log.evidence else [],
            effect_artifacts=[log.evidence[0].evidence_id] if log.evidence else [],
            predecessor=prev_decision_id,
            successors=next_roles,
            signer=signer,
        )
        # Overwrite the auto timestamp with game time, then RE-SIGN.
        d.timestamp = ts
        payload = Decision.canonical_bytes(d)
        d.signature = signer.sign(payload).hex()
        d.signer_public_key = signer.public_key_hex
        log.append_decision(d)
        prev_decision_id = d.decision_id

    print(f"Logged {len(log.decisions)} golden-path decisions")

    # 4. Log beat events as Evidence with proper timestamps
    for beat in scenario["beats"]:
        minutes = beat["gameTimeMinutes"]
        ts = base + timedelta(minutes=minutes)
        for ev in beat["events"]:
            e = Evidence.from_bytes(
                source=ev.get("source", "unknown"),
                custodian=", ".join(ev.get("visibleTo", [])),
                data=json.dumps(ev, ensure_ascii=False).encode("utf-8"),
                description=f"[{beat['id']}] {ev['type']}: {ev['title'][:60]}",
            )
            e.timestamp = ts
            log.append_evidence(e)

    save_log(log, OUT_LOG)
    print()
    print(f"Log written to: {OUT_LOG}")
    print(f"  Evidence:  {len(log.evidence)}")
    print(f"  Decisions: {len(log.decisions)}")
    print()
    print("Run:")
    print(f"  heptagon audit {OUT_LOG}")
    print(f"  heptagon seal {OUT_LOG} --sign-with {OUT_KEY}")
    print(f"  heptagon audit {OUT_LOG}")


if __name__ == "__main__":
    main()
