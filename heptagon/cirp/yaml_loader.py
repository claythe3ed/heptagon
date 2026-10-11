"""
yaml_loader.py
==============

Load a Cyber Incident Response Plan from YAML and compile it into a
CIRPModel instance.

The YAML format is defined by ``heptagon/schemas/cirp.schema.json``.
Validation runs before construction, so the loader fails fast on
malformed plans instead of producing a half-built CIRPModel.

The schema is loaded via ``importlib.resources`` so it is found
regardless of whether Heptagon is running from the source tree, an
editable install, a wheel, or a zipped egg.

Usage
-----
    from heptagon.cirp.yaml_loader import load_cirp_from_yaml
    cirp = load_cirp_from_yaml("path/to/cirp.yaml")
    report = cirp.verify_all()
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, Dict, List, Union

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from heptagon.cirp.model import (
    CIRPModel,
    Scenario,
    Stakeholder,
    Team,
)


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

def _load_schema() -> Dict[str, Any]:
    """
    Load the CIRP JSON schema from wherever the package is installed.

    Uses ``importlib.resources`` so the schema is found regardless of
    the current working directory or install method.
    """
    schema_file = files("heptagon.schemas").joinpath("cirp.schema.json")
    with schema_file.open("r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_plan_dict(plan: Dict[str, Any]) -> None:
    """
    Validate a plan dictionary against the JSON schema.

    Raises
    ------
    jsonschema.exceptions.ValidationError
        If the plan does not conform to the schema.
    """
    schema = _load_schema()
    Draft202012Validator(schema).validate(plan)


# ---------------------------------------------------------------------------
# Constructors — dict → CIRPModel primitives
# ---------------------------------------------------------------------------

def _build_teams(raw_teams: List[Dict[str, Any]]) -> List[Team]:
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


def _build_stakeholders(raw: List[Dict[str, Any]]) -> List[Stakeholder]:
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


def _build_scenarios(raw: List[Dict[str, Any]]) -> List[Scenario]:
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_cirp_from_dict(plan: Dict[str, Any]) -> CIRPModel:
    """
    Compile a validated plan dictionary into a CIRPModel.

    Runs schema validation first, then constructs the model. All
    schema-invalid input raises ValidationError before any partial
    CIRPModel is built.
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
    Load and compile a CIRP from a YAML file on disk.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        plan = yaml.safe_load(f)
    if not isinstance(plan, dict):
        raise ValueError(
            f"YAML root must be a mapping, got {type(plan).__name__}"
        )
    return build_cirp_from_dict(plan)


def load_cirp_from_yaml_string(text: str) -> CIRPModel:
    """
    Load and compile a CIRP from a YAML string.
    """
    plan = yaml.safe_load(text)
    if not isinstance(plan, dict):
        raise ValueError(
            f"YAML root must be a mapping, got {type(plan).__name__}"
        )
    return build_cirp_from_dict(plan)


__all__ = [
    "validate_plan_dict",
    "build_cirp_from_dict",
    "load_cirp_from_yaml",
    "load_cirp_from_yaml_string",
]
