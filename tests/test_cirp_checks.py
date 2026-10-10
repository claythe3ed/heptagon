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



def test_break_glass_fails_when_not_marked():
    """A break-glass decision without 'break_glass' in rationale is flagged."""
    c = _make_complete_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new("response", "Emergency admin recovery", [ev.evidence_id],
                     break_glass=True)
    c.log_decision(d)
    result = c.check_break_glass_logged()
    assert result["ok"] is False
    assert d.decision_id in result["unmarked_break_glass"]


def test_break_glass_fails_when_no_evidence():
    """A break-glass decision without evidence refs is flagged."""
    c = _make_complete_cirp()
    d = Decision.new("response", "break_glass access to recover", [],
                     break_glass=True)
    c.log_decision(d)
    result = c.check_break_glass_logged()
    assert result["ok"] is False
    assert d.decision_id in result["unmarked_break_glass"]


def test_break_glass_passes_when_marked_and_evidenced():
    """Well-formed break-glass passes."""
    c = _make_complete_cirp()
    ev = Evidence.from_bytes("soc", "analyst", b"x", "d")
    c.log_evidence(ev)
    d = Decision.new("response", "break_glass to recover admin access",
                     [ev.evidence_id], break_glass=True)
    c.log_decision(d)
    result = c.check_break_glass_logged()
    assert result["ok"] is True



def test_teams_complete_fails_when_empty():
    """A CIRP with no teams must fail — all 5 roles are missing."""
    c = CIRPModel(name="empty")
    result = c.check_teams_complete()
    assert result["ok"] is False
    assert len(result["missing_roles"]) == 5
    assert result["missing_roles"] == [
        "crisis_mgmt", "cyber_mgmt", "product_owner", "response", "third_party"
    ]


def test_teams_complete_fails_when_one_role_missing():
    """Missing any of the 5 R-C-C-P-T roles must fail the check."""
    c = CIRPModel(name="partial")
    c.add_team(Team("response", ["a"], "+1", "+2", "fix"))
    c.add_team(Team("cyber_mgmt", ["b"], "+1", "+2", "supervise"))
    c.add_team(Team("crisis_mgmt", ["c"], "+1", "+2", "handle"))
    c.add_team(Team("product_owner", ["d"], "+1", "+2", "own"))
    # third_party deliberately missing
    result = c.check_teams_complete()
    assert result["ok"] is False
    assert result["missing_roles"] == ["third_party"]


def test_teams_complete_fails_when_present_team_is_incomplete():
    """A present team missing a field must fail the check."""
    c = CIRPModel(name="incomplete")
    c.add_team(Team("response", ["a"], "+1", "+2", "fix"))
    c.add_team(Team("cyber_mgmt", ["b"], "+1", "+2", "supervise"))
    c.add_team(Team("crisis_mgmt", ["c"], "+1", "+2", "handle"))
    c.add_team(Team("product_owner", ["d"], "+1", "+2", "own"))
    # third_party present but no backup contact
    c.add_team(Team("third_party", ["e"], "+1", "", "help"))
    result = c.check_teams_complete()
    assert result["ok"] is False
    assert "third_party" in result["incomplete_teams"]


def test_teams_complete_passes_when_all_5_present_and_complete():
    """All 5 roles present and complete must pass."""
    c = _make_complete_cirp()
    result = c.check_teams_complete()
    assert result["ok"] is True
    assert result["missing_roles"] == []
    assert result["incomplete_teams"] == []
