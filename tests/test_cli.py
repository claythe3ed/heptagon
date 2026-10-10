"""
Tests for the Heptagon CLI (heptagon.cli.main).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.cli.main import main


REFERENCE = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "cirp-reference.yaml"
)


def test_declare_reference_plan(capsys):
    rc = main(["declare", str(REFERENCE)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "reference_cirp" in out
    assert "1.0" in out
    assert "response" in out
    assert "ransomware" in out


def test_declare_json_output(capsys):
    rc = main(["declare", str(REFERENCE), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["name"] == "reference_cirp"
    assert data["teams"] == 5
    assert data["scenarios"] == 3


def test_declare_missing_file(capsys):
    rc = main(["declare", "/nonexistent/path.yaml"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "ERROR" in err


def test_verify_reference_plan_fails_without_evidence(capsys):
    """A plan with no logged evidence cannot pass all checks."""
    rc = main(["verify", str(REFERENCE)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "no_hidden_thing" in out
    assert "FAIL" in out


def test_verify_json_output(capsys):
    rc = main(["verify", str(REFERENCE), "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert data["cirp_name"] == "reference_cirp"
    assert "checks" in data
    assert "7d_completeness" in data["checks"]


def test_simulate_valid_scenario(capsys):
    rc = main(["simulate", "data_breach",
               "--plan", str(REFERENCE), "--rounds", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "data_breach" in out
    assert "Valid:    True" in out


def test_simulate_detects_unknown_scenario(capsys):
    rc = main(["simulate", "does_not_exist", "--plan", str(REFERENCE)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "unknown scenario" in err.lower()


def test_simulate_json_output(capsys):
    rc = main(["simulate", "data_breach",
               "--plan", str(REFERENCE),
               "--rounds", "5", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["scenario"] == "data_breach"
    assert data["escalation_valid"] is True


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "heptagon" in out


def test_no_command_raises_systemexit():
    """Required subcommand missing -> argparse SystemExit(2)."""
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 2
