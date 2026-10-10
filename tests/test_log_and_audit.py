"""
Tests for incident log serialization (heptagon.audit.log) and the
heptagon audit CLI command.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.audit.log import IncidentLog, load_log, save_log
from heptagon.audit.signing import Signer
from heptagon.cli.main import main
from heptagon.cirp.model import Decision, Evidence


def _make_signed_log(tmp_path, tamper=False):
    """Build a small signed incident log on disk. Return its path."""
    signer = Signer.generate()

    log = IncidentLog()
    ev1 = Evidence.from_bytes("soc", "analyst", b"alert-001", "initial alert")
    ev2 = Evidence.from_bytes("edr", "engineer", b"memory-dump", "memory image")
    log.append_evidence(ev1)
    log.append_evidence(ev2)

    d1 = Decision.new(
        "cyber_mgmt", "isolate host-12",
        evidence_refs=[ev1.evidence_id, ev2.evidence_id],
        effect_artifacts=[ev2.evidence_id],
        predecessor="response",
        successors=["crisis_mgmt"],
        signer=signer,
    )
    d2 = Decision.new(
        "response", "break glass recovery",
        evidence_refs=[ev1.evidence_id],
        effect_artifacts=[ev1.evidence_id],
        predecessor="response",
        successors=["cyber_mgmt"],
        signer=signer,
        break_glass=True,
    )
    log.append_decision(d1)
    log.append_decision(d2)

    path = tmp_path / "incidents.jsonl"
    save_log(log, path)

    if tamper:
        lines = path.read_text().splitlines()
        rec = json.loads(lines[2])  # d1 is line 3 (0-indexed 2)
        rec["data"]["rationale"] = "TAMPERED"
        lines[2] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n")

    return path


# ----------------------------- Log round-trip -----------------------------

def test_log_roundtrip_preserves_evidence():
    log = IncidentLog()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "desc")
    log.append_evidence(ev)

    restored = IncidentLog.from_jsonl(log.to_jsonl())
    assert len(restored.evidence) == 1
    assert restored.evidence[0].evidence_id == ev.evidence_id
    assert restored.evidence[0].sha256 == ev.sha256


def test_log_roundtrip_preserves_decision():
    log = IncidentLog()
    d = Decision.new("cyber_mgmt", "isolate", ["ev-1"],
                     effect_artifacts=["ev-2"], predecessor="response")
    log.append_decision(d)

    restored = IncidentLog.from_jsonl(log.to_jsonl())
    r = restored.decisions[0]
    assert r.decision_id == d.decision_id
    assert r.actor == d.actor
    assert r.effect_artifacts == d.effect_artifacts
    assert r.predecessor == d.predecessor


def test_log_rejects_invalid_json():
    with pytest.raises(ValueError, match="invalid JSON"):
        IncidentLog.from_jsonl("{not json}\n")


def test_log_rejects_unknown_record_type():
    line = json.dumps({"type": "unknown", "data": {}}) + "\n"
    with pytest.raises(ValueError, match="unknown record type"):
        IncidentLog.from_jsonl(line)


def test_log_skips_blank_lines():
    log = IncidentLog()
    ev = Evidence.from_bytes("s", "c", b"x", "d")
    log.append_evidence(ev)
    text = log.to_jsonl() + "\n\n\n"
    restored = IncidentLog.from_jsonl(text)
    assert len(restored.evidence) == 1


def test_save_and_load_file(tmp_path):
    log = IncidentLog()
    log.append_evidence(Evidence.from_bytes("s", "c", b"x", "d"))
    path = tmp_path / "out.jsonl"
    save_log(log, path)
    assert path.exists()
    loaded = load_log(path)
    assert len(loaded.evidence) == 1


# ------------------------------ CLI audit --------------------------------

def test_cli_audit_clean_log_passes(tmp_path, capsys):
    path = _make_signed_log(tmp_path, tamper=False)
    rc = main(["audit", str(path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Ed25519 valid: 2" in out
    assert "OK: True" in out


def test_cli_audit_tampered_log_fails(tmp_path, capsys):
    path = _make_signed_log(tmp_path, tamper=True)
    rc = main(["audit", str(path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Ed25519 valid: 1" in out
    assert "Invalid signatures (1)" in out
    assert "OK: False" in out


def test_cli_audit_json_output(tmp_path, capsys):
    path = _make_signed_log(tmp_path, tamper=False)
    rc = main(["audit", str(path), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["evidence_count"] == 2
    assert data["decision_count"] == 2
    assert data["signatures"]["valid_ed25519"] == 2
    assert data["ok"] is True


def test_cli_audit_missing_file(capsys):
    rc = main(["audit", "/nonexistent/whatever.jsonl"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "ERROR" in err


def test_cli_audit_detects_missing_7d(tmp_path, capsys):
    """A signed decision with no effect_artifacts should be flagged."""
    signer = Signer.generate()
    log = IncidentLog()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    log.append_evidence(ev)
    # Deliberately omit effect_artifacts and predecessor
    d = Decision.new("cyber_mgmt", "isolate", [ev.evidence_id], signer=signer)
    log.append_decision(d)
    path = tmp_path / "incomplete.jsonl"
    save_log(log, path)

    rc = main(["audit", str(path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Incomplete 7D records" in out
    assert "F6" in out
    assert "F7" in out
