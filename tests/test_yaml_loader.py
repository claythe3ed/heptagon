"""
Tests for the YAML loader (heptagon.cirp.yaml_loader).
"""
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema.exceptions import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.cirp.yaml_loader import (
    build_cirp_from_dict,
    load_cirp_from_yaml,
    load_cirp_from_yaml_string,
    validate_plan_dict,
)


REFERENCE = Path(__file__).resolve().parent.parent / "examples" / "cirp-reference.yaml"


def _minimal_valid_dict() -> dict:
    return {
        "name": "test",
        "version": "0.1",
        "teams": [
            {"role": "response", "members": ["a"], "contact": "+1", "backup": "+2", "mandate": "fix"},
            {"role": "cyber_mgmt", "members": ["b"], "contact": "+1", "backup": "+2", "mandate": "supervise"},
            {"role": "crisis_mgmt", "members": ["c"], "contact": "+1", "backup": "+2", "mandate": "handle"},
            {"role": "product_owner", "members": ["d"], "contact": "+1", "backup": "+2", "mandate": "own"},
            {"role": "third_party", "members": ["e"], "contact": "+1", "backup": "+2", "mandate": "help"},
        ],
        "reporting_chain": [["response", "cyber_mgmt"], ["cyber_mgmt", "crisis_mgmt"]],
        "scenarios": [
            {
                "name": "test_scenario",
                "triggers": ["x"],
                "escalation": ["response", "cyber_mgmt"],
                "key_considerations": [],
            },
        ],
    }


def test_reference_yaml_loads():
    """The bundled reference plan must load cleanly."""
    cirp = load_cirp_from_yaml(REFERENCE)
    assert cirp.name == "reference_cirp"
    assert cirp.version == "1.0"
    assert len(cirp.teams) == 5
    assert len(cirp.reporting_chain) == 4
    assert len(cirp.scenarios) == 3
    assert len(cirp.stakeholders) == 3


def test_minimal_valid_dict_compiles():
    cirp = build_cirp_from_dict(_minimal_valid_dict())
    assert cirp.name == "test"
    assert len(cirp.teams) == 5


def test_missing_required_field_fails():
    bad = _minimal_valid_dict()
    del bad["name"]
    with pytest.raises(ValidationError):
        validate_plan_dict(bad)


def test_only_four_teams_fails_schema():
    bad = _minimal_valid_dict()
    bad["teams"] = bad["teams"][:4]
    with pytest.raises(ValidationError):
        validate_plan_dict(bad)


def test_unknown_team_role_fails_schema():
    bad = _minimal_valid_dict()
    bad["teams"][0]["role"] = "made_up_role"
    with pytest.raises(ValidationError):
        validate_plan_dict(bad)


def test_reporting_chain_edge_wrong_arity_fails():
    bad = _minimal_valid_dict()
    bad["reporting_chain"][0] = ["only_one_element"]
    with pytest.raises(ValidationError):
        validate_plan_dict(bad)


def test_load_from_string():
    text = yaml.safe_dump(_minimal_valid_dict())
    cirp = load_cirp_from_yaml_string(text)
    assert cirp.name == "test"


def test_non_mapping_root_raises():
    with pytest.raises(ValueError, match="YAML root must be a mapping"):
        load_cirp_from_yaml_string("- a\n- b\n")


def test_reference_plan_has_no_structural_gap_in_safe_scenarios():
    """data_breach and phishing_compromise must validate cleanly."""
    cirp = load_cirp_from_yaml(REFERENCE)
    result = cirp.run_tabletop("data_breach", num_rounds=5)
    assert result["escalation_valid"] is True
    result = cirp.run_tabletop("phishing_compromise", num_rounds=5)
    assert result["escalation_valid"] is True
