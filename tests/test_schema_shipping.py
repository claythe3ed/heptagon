"""
Regression test for v1.0.1 — schema shipping.
==============================================

In v1.0.0 the JSON schema lived at the repo root under ``schemas/``.
Setuptools only ships what is inside the ``heptagon/`` package, so
``pip install heptagon7`` produced a wheel that could not find its
own schema. The ``heptagon declare`` and ``heptagon verify``
commands failed on any fresh install.

This test suite locks in the fix:

  1. The schema must be loadable via ``importlib.resources``.
  2. Loading must succeed from any working directory.
  3. The schema file must live inside the ``heptagon`` package,
     not at a cwd-relative path outside it.
  4. The ``heptagon.schemas`` subpackage must be importable so
     setuptools treats it as package data.
"""

from __future__ import annotations

import sys
from importlib.resources import files
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

def test_schema_loads_from_package():
    """The schema loader must succeed and return a valid JSON Schema."""
    from heptagon.cirp.yaml_loader import _load_schema

    schema = _load_schema()

    assert schema["title"] == "CIRP Plan"
    assert "$schema" in schema
    assert "properties" in schema
    assert "teams" in schema["properties"]
    assert "reporting_chain" in schema["properties"]
    assert "scenarios" in schema["properties"]


def test_schema_loads_from_different_cwd(tmp_path, monkeypatch):
    """
    Running from a directory with no ``schemas/`` folder must still
    work, because the schema is found via the installed package.
    """
    monkeypatch.chdir(tmp_path)

    from heptagon.cirp.yaml_loader import _load_schema

    schema = _load_schema()
    assert schema["title"] == "CIRP Plan"


# ---------------------------------------------------------------------------
# Schema location
# ---------------------------------------------------------------------------

def test_schema_lives_inside_package():
    """
    The schema must resolve inside the ``heptagon`` package.
    In an editable install the package sits inside cwd — that is
    fine. The property that matters is: the schema lives under
    ``heptagon/``, not under a top-level ``schemas/`` folder.
    """
    import heptagon

    package_dir = Path(heptagon.__file__).resolve().parent
    schema_file = files("heptagon.schemas").joinpath("cirp.schema.json")
    resolved = Path(str(schema_file)).resolve()

    assert schema_file.is_file(), f"schema not found at {schema_file}"
    assert str(resolved).startswith(str(package_dir)), (
        f"schema resolved outside the package:\n"
        f"  schema:  {resolved}\n"
        f"  package: {package_dir}"
    )


def test_schema_file_is_json():
    """The packaged schema must be parseable as JSON."""
    import json

    schema_file = files("heptagon.schemas").joinpath("cirp.schema.json")
    with schema_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, dict)
    assert data["title"] == "CIRP Plan"


# ---------------------------------------------------------------------------
# Package structure
# ---------------------------------------------------------------------------

def test_schemas_subpackage_importable():
    """The ``heptagon.schemas`` subpackage must be importable."""
    import heptagon.schemas

    assert heptagon.schemas.__doc__ is not None
    assert isinstance(heptagon.schemas.__doc__, str)


def test_no_top_level_schemas_directory():
    """
    Guard against regression: the old top-level ``schemas/`` folder
    at the repo root must not exist. If it reappears, someone has
    broken the fix.
    """
    repo_root = Path(__file__).resolve().parent.parent
    top_level_schemas = repo_root / "schemas"

    assert not top_level_schemas.exists(), (
        f"top-level schemas/ folder reappeared at {top_level_schemas}. "
        f"The schema must live inside the heptagon/ package."
    )


# ---------------------------------------------------------------------------
# End-to-end validation path
# ---------------------------------------------------------------------------

def test_yaml_validation_works_with_packaged_schema():
    """
    Full path: parse a YAML plan, validate it against the packaged
    schema. Fails in v1.0.0 because the schema could not be located.
    """
    from heptagon.cirp.yaml_loader import load_cirp_from_yaml_string

    minimal_plan = """
name: smoke_test
version: "1.0"
teams:
  - role: response
    members: [a]
    contact: "+1"
    backup: "+2"
    mandate: "fix"
  - role: cyber_mgmt
    members: [b]
    contact: "+1"
    backup: "+2"
    mandate: "supervise"
  - role: crisis_mgmt
    members: [c]
    contact: "+1"
    backup: "+2"
    mandate: "handle"
  - role: product_owner
    members: [d]
    contact: "+1"
    backup: "+2"
    mandate: "own"
  - role: third_party
    members: [e]
    contact: "+1"
    backup: "+2"
    mandate: "help"
reporting_chain:
  - [response, cyber_mgmt]
  - [cyber_mgmt, crisis_mgmt]
scenarios:
  - name: test_scenario
    triggers: [x]
    escalation: [response, cyber_mgmt]
    key_considerations: []
"""

    cirp = load_cirp_from_yaml_string(minimal_plan)
    assert cirp.name == "smoke_test"
    assert len(cirp.teams) == 5
    assert len(cirp.scenarios) == 1
