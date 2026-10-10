"""
Tests that prove the CIRP compliance checks can fail.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.cirp.model import (
    CIRPModel, Team, Evidence, Decision,
)


def _make_complete_cirp() -> CIRPModel:
    c = CIRPModel(name="test")
    c.add_team(Team("response", ["a"], "+1", "+2", "fix"))
    c.add_team(Team("cyber_mgmt", ["b"], "+1", "+2", "supervise"))
    c.add_team(Team("crisis_mgmt", ["c"], "+1", "+2", "handle"))
    c.add_team(Team("product_owner", ["d"], "+1", "+2", "own"))
    c.add_team(Team("third_party", ["e"], "+1", "+2", "help"))
    c.add_reporting_edge("response", "cyber_mgmt")
    c.add_reporting_edge("cyber_mgmt", "crisis_mgmt")
    return c


def test_no_hidden_thing_fails_when_no_evidence():
    """Empty record must fail the check."""
    c = _make_complete_cirp()
    result = c.check_no_hidden_thing()
    assert result["ok"] is False


def test_no_hidden_thing_fails_when_decision_unsigned():
    """A decision without a signature breaks the record."""
    c = _make_complete_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new("cyber_mgmt", "isolate", [ev.evidence_id])
    d.signature = ""
    c.log_decision(d)
    result = c.check_no_hidden_thing()
    assert result["ok"] is False
    assert d.decision_id in result["unsigned_decisions"]


def test_no_hidden_thing_passes_with_clean_record():
    """A well-formed record must pass."""
    c = _make_complete_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new("cyber_mgmt", "isolate", [ev.evidence_id])
    c.log_decision(d)
    result = c.check_no_hidden_thing()
    assert result["ok"] is True, result
