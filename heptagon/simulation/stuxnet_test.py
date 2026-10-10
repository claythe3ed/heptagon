"""
stuxnet_test.py
===============

Run the symbolic model + internal simulator on a Stuxnet-inspired scenario.

This is a structural validation: the model receives only agent roles and
a plausibility-derived influence matrix. It is NOT told:
  - Which agents are malicious
  - How the incident unfolded historically
  - Which agents played which real-world roles

Whatever the model concludes is derived, not seeded.

History
-------
The results printed by this script are the FIRST time the scenario has
ever been executed end-to-end. Earlier documentation claimed specific
output (malicious = [intel_agency, contractor_X]) but that was written
before the simulator existed. The real output differs — see the printed
verdict for the actual derivation.
"""

from __future__ import annotations

import numpy as np

from heptagon.core.symbolic import (
    Lineage,
    MoralJacobians,
    PresentationOperator,
    UnifiedEvaluation,
)
from heptagon.simulation.internal_simulator import build_stuxnet_scenario


def run_stuxnet_test() -> dict:
    print("=" * 64)
    print("STUXNET-INSPIRED SCENARIO")
    print("Model does NOT know the historical truth.")
    print("=" * 64)

    sim = build_stuxnet_scenario()
    verdict = sim.run()

    print("\n[Simulator verdict]")
    print(f"  rounds          : {verdict['rounds']}")
    print(f"  num agents      : {verdict['num_agents']}")
    print(f"  malicious       : {verdict['malicious_agents']}")
    print(f"  benign          : {verdict['benign_agents']}")
    print(f"  influence_norm  : {verdict['influence_norm']:.4f}")

    print("\n[Final states]")
    for agent_id, state in verdict["final_states"].items():
        print(f"  {agent_id:<15} {state:+.4f}")

    # --- Symbolic layer ---
    labels = [a.id for a in sim.agents]
    lineage = Lineage(labels=labels)
    N = lineage.N

    life_paths = []
    for agent in sim.agents:
        path = np.array(
            [r.reactions[agent.id] for r in sim.timeline]
        )
        life_paths.append(path)

    influence = sim.influence.copy()
    np.fill_diagonal(influence, 0.0)

    presenter = PresentationOperator(num_agents=N)
    presentations = presenter.present(life_paths, influence)
    coverage = presenter.coverage_matrix(influence)

    print("\n[Presentation coverage]")
    print(f"  shape           : {coverage.shape}")
    print(f"  total edges     : {int(coverage.sum())}")
    print(f"  presentation len: {[len(p) for p in presentations]}")

    responsibility = np.array([a.intent_bias for a in sim.agents])
    jac = MoralJacobians(responsibility=responsibility, influence=influence)
    print("\n[Moral Jacobians]")
    print(f"  responsibility diagonal?   {jac.responsibility_is_diagonal()}")
    print(f"  influence non-diagonal?    {jac.influence_is_non_diagonal()}")

    S = np.vstack(life_paths)
    ev = UnifiedEvaluation(global_sections=S, observers=S.copy())
    metrics = ev.rank_metrics()
    print("\n[Unified evaluation]")
    print(f"  shape           : {ev.evaluate().shape}")
    print(f"  faithful?       : {ev.is_faithful()}")
    print(f"  rank deficiency : {ev.rank_deficiency()}")
    print(f"  distinctness    : {ev.distinctness_fraction():.4f}")
    print(f"  M, K, D         : {metrics['M']}, {metrics['K']}, {metrics['D']}")

    print("\n[Top influence edges]")
    edges = []
    for i in range(N):
        for j in range(N):
            if influence[i, j] > 0.5:
                edges.append((labels[i], labels[j], influence[i, j]))
    edges.sort(key=lambda x: -x[2])
    for src, dst, w in edges[:8]:
        print(f"  {src:>14s} -> {dst:<18s}  w={w:.2f}")

    return {
        "sim": sim,
        "verdict": verdict,
        "jacobians": jac,
        "evaluation": ev,
        "metrics": metrics,
    }


if __name__ == "__main__":
    run_stuxnet_test()
