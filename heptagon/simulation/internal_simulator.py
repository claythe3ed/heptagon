"""
internal_simulator.py
=====================

A lightweight, numpy-only agent simulator used for tabletop exercises.

Purpose
-------
Given a list of agent profiles (roles with intent bias and influence
capacity) and an influence matrix, run N rounds of interaction and
produce a timeline plus a verdict classifying agents as benign or
malicious based on their final state.

This replaces heavier LLM-backed agent simulators when:
  - The environment has no GPU or API keys available
  - Deterministic, reproducible results are required
  - Only the causal structure of interactions matters
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np


@dataclass
class AgentProfile:
    """A single participant in the tabletop exercise."""
    id: str
    role: str
    intent_bias: float
    influence_capacity: float
    memory: List[str] = field(default_factory=list)


@dataclass
class SimulationRound:
    """One round of the simulation."""
    round_id: int
    actions: Dict[str, float]
    reactions: Dict[str, float]


@dataclass
class InternalSimulator:
    """Deterministic tabletop simulator."""
    agents: List[AgentProfile]
    influence: np.ndarray
    rounds: int = 10
    seed: int = 42

    timeline: List[SimulationRound] = field(default_factory=list)
    final_states: Optional[np.ndarray] = None
    verdict: Optional[Dict] = None

    def run(self) -> Dict:
        """Run the simulation and return the verdict dict."""
        # Reset internal state so repeated runs are idempotent
        self.timeline = []
        self.verdict = None
        self.final_states = None

        N = len(self.agents)
        states = np.array(
            [a.intent_bias for a in self.agents], dtype=float
        )

        for r in range(self.rounds):
            actions = {
                self.agents[i].id:
                    float(states[i] * self.agents[i].influence_capacity)
                for i in range(N)
            }
            delta = self.influence.T @ np.array(list(actions.values()))
            states = np.clip(states + delta * 0.3, -1.0, 1.0)
            reactions = {
                self.agents[i].id: float(states[i]) for i in range(N)
            }
            self.timeline.append(SimulationRound(r, actions, reactions))

        self.final_states = states
        malicious = [
            self.agents[i].id for i in range(N) if states[i] < -0.3
        ]
        benign = [
            self.agents[i].id for i in range(N) if states[i] > 0.3
        ]
        self.verdict = {
            "rounds": self.rounds,
            "num_agents": N,
            "malicious_agents": malicious,
            "benign_agents": benign,
            "final_states": {
                self.agents[i].id: float(states[i]) for i in range(N)
            },
            "influence_norm": float(np.linalg.norm(self.influence)),
        }
        return self.verdict


def build_stuxnet_scenario() -> InternalSimulator:
    """
    Build the Stuxnet-inspired scenario.

    The model is given ONLY roles and a plausible influence matrix.
    It is not told which agents are malicious, or how the incident
    unfolded historically.
    """
    agents = [
        AgentProfile("engineer_A",   "centrifuge_operator",   +0.4, 0.3),
        AgentProfile("engineer_B",   "centrifuge_operator",   +0.2, 0.2),
        AgentProfile("contractor_X", "industrial_contractor", -0.1, 0.5),
        AgentProfile("intel_agency", "foreign_intelligence",  -0.8, 0.9),
        AgentProfile("security_firm", "antivirus_vendor",     +0.7, 0.6),
        AgentProfile("usb_carrier",  "field_technician",       0.0, 0.8),
        AgentProfile("plant_manager", "site_manager",         +0.5, 0.4),
        AgentProfile("journalist",   "media",                 +0.3, 0.7),
    ]
    N = len(agents)
    inf = np.zeros((N, N))
    # Row = source (influencer), column = target (influenced)
    inf[3, 2] = 0.8    # intel_agency -> contractor_X
    inf[2, 5] = 0.9    # contractor_X -> usb_carrier
    inf[5, 0] = 0.9    # usb_carrier  -> engineer_A
    inf[5, 1] = 0.9    # usb_carrier  -> engineer_B
    inf[0, 6] = 0.6    # engineer_A   -> plant_manager
    inf[1, 6] = 0.5    # engineer_B   -> plant_manager
    inf[6, 4] = 0.7    # plant_manager -> security_firm
    inf[4, 7] = 0.8    # security_firm -> journalist
    return InternalSimulator(
        agents=agents, influence=inf, rounds=10, seed=2025
    )
