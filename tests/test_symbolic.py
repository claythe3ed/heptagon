"""
Tests for incident_response.py
Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heptagon.core.symbolic import (
    FiberBundle7D,
    MoralSheaf,
    Lineage,
    PresentationOperator,
    TestimonyOperator,
    MoralJacobians,
    UnifiedEvaluation,
    IncidentResponsePipeline,
)


def test_bundle_dim():
    b = FiberBundle7D()
    assert b.total_dim == 7
    p = b.point([0, 0, 0, 0], nu=1.0, alpha=2.0, lam=3.0)
    assert p.shape == (7,)
    assert p[-3] == 1.0 and p[-2] == 2.0 and p[-1] == 3.0


def test_sheaf_flabby():
    g = np.array([1.0, 2.0, 3.0])
    s = MoralSheaf(global_section=g)
    s.add_local("A", g)
    assert s.is_flabby() is True
    s.add_local("B", g + 1.0)
    assert s.is_flabby() is False


def test_recording_injective():
    deeds = np.eye(4)
    records = np.eye(4)
    assert MoralSheaf.recording_map_is_injective(deeds, records) is True


def test_lineage_ancestor():
    lin = Lineage(labels=[f"p{i}" for i in range(5)])
    assert lin.is_ancestor(0, 4) is True
    assert lin.is_ancestor(4, 0) is False
    assert lin.ancestors_of(3) == [0, 1, 2]


def test_presentation_operator():
    rng = np.random.default_rng(0)
    N = 4
    paths = [rng.normal(size=3) for _ in range(N)]
    inf = np.ones((N, N)) - np.eye(N)
    op = PresentationOperator(N)
    out = op.present(paths, inf)
    assert len(out) == N
    cov = op.coverage_matrix(inf)
    assert cov.shape == (N, N)
    assert np.all(np.diag(cov) == 0)


def test_testimony_operator():
    rng = np.random.default_rng(3)
    N = 5
    paths = [rng.normal(size=4) for _ in range(N)]
    weights = rng.uniform(0, 1, size=(N, 3))
    op = TestimonyOperator(N)
    out = op.witness(paths, weights)
    assert len(out) == N
    # own (4) + outer(3,4).ravel() = 4 + 12 = 16
    assert out[0].shape == (4 + 12,)
    M = op.attestation_matrix(weights)
    assert M.shape == (N, 3)


def test_moral_jacobians():
    resp = np.array([1.0, -1.0, 0.5])
    inf = np.array([
        [0.0, 0.5, 0.0],
        [0.0, 0.0, 0.7],
        [0.0, 0.0, 0.0],
    ])
    # No observation provided -> property is unverified (None)
    j = MoralJacobians(resp, inf)
    assert j.responsibility_is_diagonal() is None
    assert j.influence_is_non_diagonal() is True
    assert np.allclose(j.full_jacobian(), np.diag(resp))
    assert np.allclose(j.influence_column(2), inf[:, 2])
    assert np.allclose(j.influence_row(0), inf[0])


def test_moral_jacobians_with_observed_diagonal():
    """An observed Jacobian that IS diagonal must verify True."""
    resp = np.array([1.0, -1.0, 0.5])
    inf = np.zeros((3, 3))
    observed = np.diag([0.9, -0.8, 0.4])
    j = MoralJacobians(resp, inf, observed_jacobian=observed)
    assert j.responsibility_is_diagonal() is True


def test_moral_jacobians_with_observed_off_diagonal():
    """An observed Jacobian with nonzero off-diagonal must verify False."""
    resp = np.array([1.0, -1.0, 0.5])
    inf = np.zeros((3, 3))
    observed = np.diag([0.9, -0.8, 0.4]).astype(float)
    observed[0, 1] = 0.5
    j = MoralJacobians(resp, inf, observed_jacobian=observed)
    assert j.responsibility_is_diagonal() is False


def test_moral_jacobians_shape_mismatch_observed():
    """observed_jacobian must match shape (n, n)."""
    import pytest as _pytest
    resp = np.array([1.0, 2.0])
    inf = np.zeros((2, 2))
    with _pytest.raises(ValueError):
        MoralJacobians(resp, inf, observed_jacobian=np.zeros((3, 3)))


def test_moral_jacobians_shape_mismatch():
    with pytest.raises(ValueError):
        MoralJacobians(np.array([1.0, 2.0]), np.zeros((3, 3)))


def test_unified_evaluation():
    rng = np.random.default_rng(1)
    S = rng.normal(size=(4, 3))
    V = rng.normal(size=(3, 3))
    ev = UnifiedEvaluation(global_sections=S, observers=V)
    E = ev.evaluate()
    assert E.shape == (3, 4)
    assert ev.is_faithful() is True


def test_pipeline_end_to_end():
    rng = np.random.default_rng(2)
    N = 6
    lin = Lineage(labels=[f"a{i}" for i in range(N)])
    paths = [rng.normal(size=5) for _ in range(N)]
    inf = rng.uniform(-1, 1, size=(N, N))
    np.fill_diagonal(inf, 0.0)
    pipe = IncidentResponsePipeline(
        lineage=lin, life_paths=paths, influence=inf,
    )
    out = pipe.run()
    assert out["num_agents"] == N
    # The pipeline does not supply an observed Jacobian, so the
    # diagonal property is unverified (None), not True.
    assert out["responsibility_diagonal"] is None
    assert isinstance(out["faithful"], bool)


def test_pipeline_requires_lineage():
    pipe = IncidentResponsePipeline()
    with pytest.raises(ValueError):
        pipe.run()



def test_rank_deficiency_respects_D_bound():
    """
    When D < min(M, K), the effective max rank is D, not min(M, K).
    The factorization E = V @ S.T constrains rank(E) <= min(M, K, D).
    """
    # S: shape (K=4, D=3) - 4 histories, each 3-dimensional
    # V: shape (M=4, D=3) - 4 observers, each projecting onto D=3 dims
    # E = V @ S.T has shape (M=4, K=4), rank <= min(4, 4, 3) = 3
    S = np.array([
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
        [1.0, 1.0, 1.0],
    ])
    V = np.array([
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
        [1.0, 1.0, 1.0],
    ])
    ev = UnifiedEvaluation(global_sections=S, observers=V)
    metrics = ev.rank_metrics()
    assert metrics["M"] == 4
    assert metrics["K"] == 4
    assert metrics["D"] == 3
    assert metrics["theoretical_max_rank"] == 4
    assert metrics["effective_max_rank"] == 3
    # Rank is bounded by D even though M and K are both 4
    assert metrics["actual_rank"] <= 3
    # Both statistics measure against the effective bound
    assert ev.rank_deficiency() >= 0
    assert ev.rank_deficiency() == 3 - metrics["actual_rank"]


def test_rank_deficiency_zero_when_full_rank():
    """A well-conditioned case achieves effective_max_rank."""
    S = np.eye(3)
    V = np.eye(3)
    ev = UnifiedEvaluation(global_sections=S, observers=V)
    assert ev.rank_deficiency() == 0
    assert ev.rank_metrics()["actual_rank"] == 3


def test_rank_deficiency_positive_when_collapsed():
    """A collapsed case must show positive deficiency."""
    # Two identical histories -> rank loss of 1
    S = np.array([
        [1.0, 0.0, 0.0],
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    ])
    V = np.eye(3)
    ev = UnifiedEvaluation(global_sections=S, observers=V)
    assert ev.rank_deficiency() == 1
