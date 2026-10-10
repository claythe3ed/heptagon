"""
Tests for Ed25519 signing (heptagon.audit.signing + Decision integration).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.audit.signing import Signer
from heptagon.cirp.model import CIRPModel, Decision, Evidence, Team


def _minimal_cirp() -> CIRPModel:
    c = CIRPModel(name="t")
    for role in ("response", "cyber_mgmt", "crisis_mgmt",
                 "product_owner", "third_party"):
        c.add_team(Team(role, ["x"], "+1", "+2", "do the thing"))
    c.add_reporting_edge("response", "cyber_mgmt")
    c.add_reporting_edge("cyber_mgmt", "crisis_mgmt")
    return c


# ---------------------------- Signer class ----------------------------

def test_signer_generate_produces_keypair():
    s = Signer.generate()
    assert len(s.private_key_bytes) == 32
    assert len(s.public_key_bytes) == 32
    assert s.public_key_hex == s.public_key_bytes.hex()


def test_signer_sign_and_verify_roundtrip():
    s = Signer.generate()
    payload = b"the message"
    sig = s.sign(payload)
    assert len(sig) == 64
    assert Signer.verify(s.public_key_bytes, payload, sig) is True


def test_verify_rejects_tampered_payload():
    s = Signer.generate()
    payload = b"original"
    sig = s.sign(payload)
    assert Signer.verify(s.public_key_bytes, b"tampered", sig) is False


def test_verify_rejects_wrong_key():
    s1 = Signer.generate()
    s2 = Signer.generate()
    sig = s1.sign(b"msg")
    assert Signer.verify(s2.public_key_bytes, b"msg", sig) is False


def test_signer_save_and_load(tmp_path):
    s = Signer.generate()
    path = tmp_path / "key.json"
    s.save(path)
    assert path.exists()

    loaded = Signer.load(path)
    assert loaded.private_key_bytes == s.private_key_bytes
    assert loaded.public_key_bytes == s.public_key_bytes


def test_signer_file_permissions(tmp_path):
    """Saved keypair must be 0600."""
    import os
    s = Signer.generate()
    path = tmp_path / "key.json"
    s.save(path)
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_signer_load_rejects_wrong_algorithm(tmp_path):
    import json
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"algorithm": "rsa"}))
    with pytest.raises(ValueError, match="unsupported algorithm"):
        Signer.load(path)


# ----------------------- Decision integration -------------------------

def test_decision_new_without_signer_uses_legacy():
    d = Decision.new("cyber_mgmt", "isolate", ["ev-1"])
    assert d.signature_algorithm == "sha256-truncated"
    assert d.signer_public_key == ""
    assert len(d.signature) == 16


def test_decision_new_with_signer_uses_ed25519():
    s = Signer.generate()
    d = Decision.new("cyber_mgmt", "isolate", ["ev-1"], signer=s)
    assert d.signature_algorithm == "ed25519"
    assert d.signer_public_key == s.public_key_hex
    assert len(d.signature) == 128  # 64 bytes hex


def test_decision_signature_verifies_with_canonical_payload():
    s = Signer.generate()
    d = Decision.new(
        "cyber_mgmt", "isolate", ["ev-1"],
        effect_artifacts=["ev-2"],
        predecessor="response",
        signer=s,
    )
    payload = Decision.canonical_bytes(d)
    ok = Signer.verify(
        bytes.fromhex(d.signer_public_key),
        payload,
        bytes.fromhex(d.signature),
    )
    assert ok is True


def test_decision_tampering_invalidates_signature():
    s = Signer.generate()
    d = Decision.new("cyber_mgmt", "isolate", ["ev-1"], signer=s)
    d.rationale = "TAMPERED"
    payload = Decision.canonical_bytes(d)
    ok = Signer.verify(
        bytes.fromhex(d.signer_public_key),
        payload,
        bytes.fromhex(d.signature),
    )
    assert ok is False


# --------------------- check_no_hidden_thing --------------------------

def test_check_no_hidden_thing_passes_with_ed25519_signed_decision():
    s = Signer.generate()
    c = _minimal_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new(
        "cyber_mgmt", "isolate", [ev.evidence_id], signer=s,
    )
    c.log_decision(d)
    result = c.check_no_hidden_thing()
    assert result["ok"] is True
    assert result["invalid_signatures"] == []


def test_check_no_hidden_thing_detects_broken_signature():
    """Tampering with the rationale after signing must fail the check."""
    s = Signer.generate()
    c = _minimal_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new("cyber_mgmt", "isolate", [ev.evidence_id], signer=s)
    d.rationale = "TAMPERED AFTER SIGNING"
    c.log_decision(d)
    result = c.check_no_hidden_thing()
    assert result["ok"] is False
    assert d.decision_id in result["invalid_signatures"]


def test_check_no_hidden_thing_lists_legacy_decisions():
    """A legacy (sha256) signed decision is flagged separately."""
    c = _minimal_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new("cyber_mgmt", "isolate", [ev.evidence_id])  # no signer
    c.log_decision(d)
    result = c.check_no_hidden_thing()
    assert d.decision_id in result["legacy_sha256_decisions"]
