"""
incident_response.py
====================

A symbolic, formal model of "Presentation in the Space of Comprehensiveness"
(al-'ard fi fada' al-shumul), adapted as a general-purpose framework for
incident response, accountability, causal tracing, and multi-agent audit.

METHODOLOGICAL NOTE
-------------------
This module is NOT physics, NOT theology, and NOT a tafsir of the Hereafter.
It is a formalization of a symbolic ijtihad: the idea that a complete
presentation of events unveils all coordinates — time, place, intention,
effect, context, outcome, lineage.

The mathematics here is a LANGUAGE for meaning, not a claim about the
unseen. It is designed for:

    1.  Multi-Agent AI Safety
    2.  Governance & Legal Accountability
    3.  Economics & Supply Chains
    4.  Public Health & Epidemics
    5.  Social Science & Public Policy
    6.  Environment & Climate Justice
    7.  Data Provenance & Information Verification
    8.  Cybersecurity & Digital Forensics
    10. Interactive Games, Narratives & Simulation
    11. Knowledge Management & Ontology
    12. Education & Training

    (9. Theology and philosophy are deliberately excluded.)

License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

import numpy as np

__version__ = "1.0.1"
__all__ = [
    "FiberBundle7D",
    "MoralSheaf",
    "Lineage",
    "PresentationOperator",
    "TestimonyOperator",
    "MoralJacobians",
    "UnifiedEvaluation",
    "IncidentResponsePipeline",
    "demo",
]


# ---------------------------------------------------------------------------
# 1. The seven-dimensional fiber bundle
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FiberBundle7D:
    """
    E = B x F5 x F6 x F7,  dim(E) = 7

    B   : base spacetime (3 space + 1 time)
    F5  : intention space           (nu)
    F6  : effect space              (alpha)
    F7  : lineage-position space    (lambda)
    """
    base_dim: int = 4
    f5_dim: int = 1
    f6_dim: int = 1
    f7_dim: int = 1

    @property
    def total_dim(self) -> int:
        return self.base_dim + self.f5_dim + self.f6_dim + self.f7_dim

    def point(self, x, nu, alpha, lam) -> np.ndarray:
        return np.concatenate([
            np.atleast_1d(x),
            np.atleast_1d(nu),
            np.atleast_1d(alpha),
            np.atleast_1d(lam),
        ])

    def describe(self) -> str:
        return (
            f"FiberBundle7D(base={self.base_dim}D, "
            f"intention={self.f5_dim}D, effect={self.f6_dim}D, "
            f"lineage={self.f7_dim}D) -> total {self.total_dim}D"
        )


# ---------------------------------------------------------------------------
# 2. The flabby-sheaf condition: "no hidden thing"
# ---------------------------------------------------------------------------

@dataclass
class MoralSheaf:
    """
    A toy sheaf F over E carrying 'moral data' (intention, word, deed, effect).

    Flabby condition: every local section extends to a global section.
    Equivalent dual: ker(rho) = {0}, i.e. the recording map is injective.
    """
    global_section: np.ndarray
    local_sections: Dict[str, np.ndarray] = field(default_factory=dict)

    def add_local(self, patch: str, data: np.ndarray) -> None:
        self.local_sections[patch] = np.asarray(data, dtype=float)


    def is_flabby(self, tol: float = 1e-10) -> bool:
        """
        A source's local section is consistent with the global record
        if, on every index where the source has nonzero data, the
        global record agrees. Sources that have no data on an index
        are not penalised for it.
        """
        if not self.local_sections:
            return True
        for local in self.local_sections.values():
            mask = np.abs(local) > 0
            if not np.allclose(local[mask], self.global_section[mask], atol=tol):
                return False
        return True

    @staticmethod
    def recording_map_is_injective(
        deeds: np.ndarray,
        records: np.ndarray,
        tol: Optional[float] = None,
    ) -> bool:
        if deeds.ndim == 1:
            M = np.column_stack([deeds, records])
        else:
            M = deeds
        rank = int(np.linalg.matrix_rank(M, tol=tol))
        return bool(rank == M.shape[1])


# ---------------------------------------------------------------------------
# 3. The lineage as a poset with a maximal chain
# ---------------------------------------------------------------------------

@dataclass
class Lineage:
    """
    (P, ≺) where p_i ≺ p_j means p_i is an ancestor / predecessor of p_j.
    P = {p_1, ..., p_N}; p_1 = root, p_N = latest node.
    """
    labels: List[str]
    predecessor: Dict[int, int] = field(init=False)

    def __post_init__(self) -> None:
        self.N = len(self.labels)
        self.predecessor = {i: i - 1 for i in range(1, self.N)}

    def is_ancestor(self, i: int, j: int) -> bool:
        return bool(0 <= i < j < self.N)

    def ancestors_of(self, j: int) -> List[int]:
        return [i for i in range(j) if self.is_ancestor(i, j)]

    def successor_state(
        self,
        s_i: np.ndarray,
        a_i: np.ndarray,
        e_i: np.ndarray,
        phi: Callable[[np.ndarray, np.ndarray, np.ndarray], np.ndarray],
    ) -> np.ndarray:
        return phi(s_i, a_i, e_i)

    def propagate(
        self,
        s0: np.ndarray,
        acts: Sequence[np.ndarray],
        envs: Sequence[np.ndarray],
        phi: Callable[[np.ndarray, np.ndarray, np.ndarray], np.ndarray],
    ) -> List[np.ndarray]:
        states = [s0]
        for i in range(self.N - 1):
            states.append(self.successor_state(states[-1], acts[i], envs[i], phi))
        return states


# ---------------------------------------------------------------------------
# 4. The Presentation operator
# ---------------------------------------------------------------------------

@dataclass
class PresentationOperator:
    """
    Pi : H -> V,  H = prod_i Gamma(gamma_i),  V = prod_i V_i
    The i-th projection Pi_i shows agent i:
        - its own life-path gamma_i
        - the causal future J^+(e) of each of its deeds.
    """
    num_agents: int

    def present(
        self,
        life_paths: Sequence[np.ndarray],
        influence: np.ndarray,
        threshold: float = 0.0,
    ) -> List[np.ndarray]:
        out: List[np.ndarray] = []
        for i in range(self.num_agents):
            own = life_paths[i]
            reached = [
                life_paths[j] * influence[i, j]
                for j in range(self.num_agents)
                if j != i and abs(influence[i, j]) > threshold
            ]
            out.append(np.concatenate([own] + reached) if reached else own)
        return out

    def coverage_matrix(self, influence: np.ndarray) -> np.ndarray:
        C = (np.abs(influence) > 0).astype(int)
        np.fill_diagonal(C, 0)
        return C


# ---------------------------------------------------------------------------
# 5. The Testimony operator
# ---------------------------------------------------------------------------

@dataclass
class TestimonyOperator:
    """
    W = (+)_i W_i,  W_i(gamma) = gamma_i (+) O_i(gamma_i)
    O_i is the 'testimony of the components': each component witnesses
    its own deed.

    Note:  __test__ = False  prevents pytest from collecting this class
    as a test case (its name starts with "Test").
    """
    __test__ = False
    num_agents: int

    def witness(
        self,
        life_paths: Sequence[np.ndarray],
        component_weights: np.ndarray,
    ) -> List[np.ndarray]:
        out: List[np.ndarray] = []
        for i in range(self.num_agents):
            own = life_paths[i]
            limbs = np.outer(component_weights[i], own).ravel()
            out.append(np.concatenate([own, limbs]))
        return out

    def attestation_matrix(self, component_weights: np.ndarray) -> np.ndarray:
        return component_weights.copy()


# ---------------------------------------------------------------------------
# 6. Responsibility (diagonal) vs. Influence (non-diagonal)
# ---------------------------------------------------------------------------

@dataclass
class MoralJacobians:
    """
    R_i = R(gamma_i)
    Responsibility is individual:
        dR_i / d gamma_j = 0  for i != j   =>  Jacobian is diagonal.
    Influence is extended:
        A_{ij} = d s_j / d a_i             =>  A is generally non-diagonal.
    """
    responsibility: np.ndarray
    influence: np.ndarray

    def __post_init__(self) -> None:
        self.responsibility = np.asarray(self.responsibility, dtype=float)
        self.influence = np.asarray(self.influence, dtype=float)
        n = self.responsibility.shape[0]
        if self.influence.shape != (n, n):
            raise ValueError(
                f"influence must be ({n},{n}), got {self.influence.shape}"
            )

    def full_jacobian(self) -> np.ndarray:
        return np.diag(self.responsibility)

    def responsibility_is_diagonal(self, tol: float = 1e-12) -> bool:
        J = self.full_jacobian()
        off = J - np.diag(np.diag(J))
        return bool(np.linalg.norm(off) < tol)

    def influence_is_non_diagonal(self, tol: float = 1e-12) -> bool:
        off = self.influence - np.diag(np.diag(self.influence))
        return bool(np.linalg.norm(off) > tol)

    def propagated_state(
        self,
        s1: np.ndarray,
        acts: np.ndarray,
        phi_power: np.ndarray,
    ) -> np.ndarray:
        return phi_power @ s1 + self.influence[:, -1] @ acts

    def responsibility_vector(self) -> np.ndarray:
        return self.responsibility.copy()

    def influence_row(self, i: int) -> np.ndarray:
        return self.influence[i].copy()

    def influence_column(self, j: int) -> np.ndarray:
        return self.influence[:, j].copy()


# ---------------------------------------------------------------------------
# 7. The unified evaluation equation
# ---------------------------------------------------------------------------

@dataclass
class UnifiedEvaluation:
    """
    ev : S x V -> C,  ev(s, v) = <pi_v(s), v>
    Faithfulness: [forall sigma: ev_sigma(s) = ev_sigma(s')] => s = s'
    i.e. the family {ev_sigma} separates points of S.
    """
    global_sections: np.ndarray
    observers: np.ndarray

    def evaluate(self) -> np.ndarray:
        return self.observers @ self.global_sections.T

    def is_faithful(self, tol: float = 1e-10) -> bool:
        E = self.evaluate()
        K = E.shape[1]
        for a in range(K):
            for b in range(a + 1, K):
                if np.allclose(E[:, a], E[:, b], atol=tol):
                    return False
        return True

    def rank_deficiency(self) -> int:
        """
        Return  max_rank - rank(E),  where max_rank = min(M, K).

        0 means the evaluation map achieves the maximum possible rank
        given the dimensions — no information lost beyond the
        unavoidable dimensional limit.
        Positive means genuine collapse.
        """
        E = self.evaluate()
        M, K = E.shape
        D = self.global_sections.shape[1]
        max_rank = min(M, K, D)
        return int(max_rank - np.linalg.matrix_rank(E))

    def distinctness_fraction(self, tol: float = 1e-10) -> float:
        """
        Fraction of column pairs (a, b) with a < b whose evaluations
        differ. 1.0 means every pair is distinguished; < 1.0 means
        genuine collapse.
        """
        E = self.evaluate()
        K = E.shape[1]
        if K < 2:
            return 1.0
        total = 0
        distinct = 0
        for a in range(K):
            for b in range(a + 1, K):
                total += 1
                if not np.allclose(E[:, a], E[:, b], atol=tol):
                    distinct += 1
        return float(distinct / total)


# ---------------------------------------------------------------------------
# 8. Integrated pipeline
# ---------------------------------------------------------------------------

@dataclass
class IncidentResponsePipeline:
    bundle: FiberBundle7D = field(default_factory=FiberBundle7D)
    lineage: Optional[Lineage] = None
    life_paths: Optional[List[np.ndarray]] = None
    influence: Optional[np.ndarray] = None
    responsibility: Optional[np.ndarray] = None
    component_weights: Optional[np.ndarray] = None

    presentations: List[np.ndarray] = field(default_factory=list)
    testimonies: List[np.ndarray] = field(default_factory=list)
    jacobians: Optional[MoralJacobians] = None
    evaluation: Optional[UnifiedEvaluation] = None

    def run(self) -> Dict:
        if self.lineage is None:
            raise ValueError("lineage must be set before run()")
        if self.life_paths is None or self.influence is None:
            raise ValueError("life_paths and influence must be set")

        N = self.lineage.N
        self.presentations = PresentationOperator(N).present(
            self.life_paths, self.influence
        )
        weights = self.component_weights
        if weights is None:
            weights = np.ones((N, 4))
        self.testimonies = TestimonyOperator(N).witness(
            self.life_paths, weights
        )
        resp = self.responsibility
        if resp is None:
            resp = np.ones(N)
        self.jacobians = MoralJacobians(resp, self.influence)

        S = np.vstack(self.life_paths)
        V = S.copy()
        self.evaluation = UnifiedEvaluation(global_sections=S, observers=V)

        return {
            "num_agents": N,
            "num_presentations": len(self.presentations),
            "num_testimonies": len(self.testimonies),
            "responsibility_diagonal": self.jacobians.responsibility_is_diagonal(),
            "influence_non_diagonal": self.jacobians.influence_is_non_diagonal(),
            "faithful": self.evaluation.is_faithful(),
            "rank_deficiency": self.evaluation.rank_deficiency(),
            "distinctness_fraction": self.evaluation.distinctness_fraction(),
        }


# ---------------------------------------------------------------------------
# 9. Demonstration
# ---------------------------------------------------------------------------

def demo(seed: int = 7, verbose: bool = True) -> Dict:
    rng = np.random.default_rng(seed=seed)

    bundle = FiberBundle7D()
    if verbose:
        print(f"[1] {bundle.describe()}")
    p = bundle.point([1.0, 0.0, 0.0, 2.0], nu=0.5, alpha=-0.3, lam=0.9)
    if verbose:
        print(f"    sample point = {np.round(p, 3)}")

    g = rng.normal(size=5)
    sheaf = MoralSheaf(global_section=g)
    sheaf.add_local("source_A", g)
    sheaf.add_local("source_B", g)
    if verbose:
        print(f"[2] sheaf flabby? {sheaf.is_flabby()}")
    deeds = rng.normal(size=(4, 3))
    records = rng.normal(size=(4, 3))
    if verbose:
        print(f"    recording map injective? "
              f"{MoralSheaf.recording_map_is_injective(deeds, records)}")

    lineage = Lineage(labels=[f"agent_{i:02d}" for i in range(1, 11)])
    if verbose:
        print(f"[3] N = {lineage.N}; agent_01 ≺ agent_10? "
              f"{lineage.is_ancestor(0, 9)}")

    N = lineage.N
    life_paths = [rng.normal(size=8) for _ in range(N)]
    influence = rng.uniform(-1, 1, size=(N, N))
    np.fill_diagonal(influence, 0.0)
    influence[np.abs(influence) < 0.6] = 0.0
    responsibility = rng.normal(size=N)

    pipe = IncidentResponsePipeline(
        bundle=bundle,
        lineage=lineage,
        life_paths=life_paths,
        influence=influence,
        responsibility=responsibility,
    )
    result = pipe.run()

    if verbose:
        print(f"[4] presentations: {len(pipe.presentations)}; "
              f"first length = {len(pipe.presentations[0])}")
        print(f"[5] testimonies:  {len(pipe.testimonies)}; "
              f"first length = {len(pipe.testimonies[0])}")
        print(f"[6] responsibility diagonal? "
              f"{result['responsibility_diagonal']}")
        print(f"    influence non-diagonal?  "
              f"{result['influence_non_diagonal']}")
        print(f"[7] evaluation shape = "
              f"{pipe.evaluation.evaluate().shape}")
        print(f"    faithful (no hidden thing)? {result['faithful']}")
        print(f"    rank deficiency = {result['rank_deficiency']}")
        print(f"    distinctness fraction = "
              f"{result['distinctness_fraction']}")

    return {"pipeline": pipe, "result": result}


if __name__ == "__main__":
    demo()
