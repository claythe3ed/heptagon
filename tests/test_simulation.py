"""
Tests for heptagon.simulation.internal_simulator.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.simulation.internal_simulator import (
    AgentProfile,
    InternalSimulator,
    build_stuxnet_scenario,
)


def test_simulator_runs_and_returns_verdict():
    sim = build_stuxnet_scenario()
    verdict = sim.run()
    assert verdict["rounds"] == 10
    assert verdict["num_agents"] == 8
    assert isinstance(verdict["malicious_agents"], list)
    assert isinstance(verdict["benign_agents"], list)


def test_simulator_is_deterministic():
    """Same seed -> identical final states."""
    v1 = build_stuxnet_scenario().run()
    v2 = build_stuxnet_scenario().run()
    for agent_id in v1["final_states"]:
        assert v1["final_states"][agent_id] == v2["final_states"][agent_id]


def test_simulator_resets_state_on_rerun():
    """Running twice on the same instance must not double-count."""
    sim = build_stuxnet_scenario()
    v1 = sim.run()
    v2 = sim.run()
    assert v1["final_states"] == v2["final_states"]
    assert len(sim.timeline) == sim.rounds


def test_simulator_timeline_length():
    sim = build_stuxnet_scenario()
    sim.run()
    assert len(sim.timeline) == sim.rounds
    for r in sim.timeline:
        assert len(r.actions) == sim.agents.__len__()
        assert len(r.reactions) == sim.agents.__len__()


def test_simulator_detects_intel_agency_as_malicious():
    """The high-negative-bias influencer must end negative."""
    verdict = build_stuxnet_scenario().run()
    assert "intel_agency" in verdict["malicious_agents"]


def test_simulator_detects_security_firm_as_benign():
    """The high-positive-bias vendor must end positive."""
    verdict = build_stuxnet_scenario().run()
    assert "security_firm" in verdict["benign_agents"]


def test_minimal_simulator():
    """A tiny 2-agent simulator must not crash."""
    agents = [
        AgentProfile("a", "role_a", +0.5, 0.5),
        AgentProfile("b", "role_b", -0.5, 0.5),
    ]
    inf = np.array([[0.0, 0.3], [0.3, 0.0]])
    sim = InternalSimulator(agents=agents, influence=inf, rounds=5, seed=1)
    verdict = sim.run()
    assert verdict["num_agents"] == 2
    assert verdict["rounds"] == 5
