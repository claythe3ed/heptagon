"""
yaml_loader.py
==============

Load a Cyber Incident Response Plan from YAML and compile it into a
CIRPModel instance.

The YAML format is defined by schemas/cirp.schema.json. Validation
runs before construction, so the loader fails fast on malformed
plans instead of producing a half-built CIRPModel.

Usage
-----
    from heptagon.cirp.yaml_loader import load_cirp_from_yaml
    cirp = load_cirp_from_yaml("path/to/cirp.yaml")
    report = cirp.verify_all()
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from heptagon.cirp.model import (
    CIRPModel,
    Decision,
    Evidence,
    Scenario,
    Stakeholder,
    Team,
)


# Locate the schema relative to the package root.
_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "schemas"
    / "cirp.schema.json"
)


def _load_schema() -> Dict[str, Any]:
    with _SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_plan_dict(plan: Dict[str, Any]) -> None:
    """
    Validate a plan dictionary against the JSON schema.

    Raises
    ------
    jsonschema.exceptions.ValidationError
        If the plan does not conform to the schema.
    """
    schema = _load_schema()
    validator = Draft202012Validator(schema)
    validator.validate(plan)


def _build_teams(raw_teams: list) -> list:
    return [
        Team(
            role=t["role"],
            members=list(t["members"]),
            contact=t["contact"],
            backup=t["backup"],
            mandate=t["mandate"],
        )
        for t in raw_teams
    ]


def _build_stakeholders(raw: list) -> list:
    return [
        Stakeholder(
            name=s["name"],
            kind=s["kind"],
            category=s["category"],
            contact=s["contact"],
            need_to_know=list(s.get("need_to_know", [])),
        )
        for s in raw
    ]


def _build_scenarios(raw: list) -> list:
    return [
        Scenario(
            name=s["name"],
            triggers=list(s.get("triggers", [])),
            escalation=list(s["escalation"]),
            key_considerations=list(s.get("key_considerations", [])),
            training_simulations=list(s.get("training_simulations", [])),
        )
        for s in raw
    ]


def build_cirp_from_dict(plan: Dict[str, Any]) -> CIRPModel:
    """
    Compile a validated plan dictionary into a CIRPModel.

    Assumes `validate_plan_dict(plan)` has already passed, or will
    raise ValidationError if it hasn't been called explicitly.
    """
    validate_plan_dict(plan)

    cirp = CIRPModel(
        name=plan["name"],
        version=plan["version"],
    )
    for team in _build_teams(plan["teams"]):
        cirp.add_team(team)
    for stakeholder in _build_stakeholders(plan.get("stakeholders", [])):
        cirp.add_stakeholder(stakeholder)
    for scenario in _build_scenarios(plan["scenarios"]):
        cirp.add_scenario(scenario)
    for reporter, target in plan["reporting_chain"]:
        cirp.add_reporting_edge(reporter, target)
    return cirp


def load_cirp_from_yaml(path: Union[str, Path]) -> CIRPModel:
    """
    Load and compile a CIRP from a YAML file.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        plan = yaml.safe_load(f)
    if not isinstance(plan, dict):
        raise ValueError(f"YAML root must be a mapping, got {type(plan).__name__}")
    return build_cirp_from_dict(plan)


def load_cirp_from_yaml_string(text: str) -> CIRPModel:
    """
    Load and compile a CIRP from a YAML string.
    """
    plan = yaml.safe_load(text)
    if not isinstance(plan, dict):
        raise ValueError(f"YAML root must be a mapping, got {type(plan).__name__}")
    return build_cirp_from_dict(plan)
