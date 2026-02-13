"""Tests for atlas.planner.path_finder — PathFinder."""

from atlas.core.models import AttackEdge, LoggingState
from atlas.core.types import EdgeType, NoiseLevel
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.path_finder import PathFinder


def _build_test_graph() -> AttackGraph:
    """Build a small attack graph with multiple paths.

    Structure:
      alice --[assume, cost=0.15]--> admin-role
      alice --[create_key, cost=0.65]--> bob --[assume, cost=0.15]--> admin-role
      alice --[attach_policy, cost=0.70]--> alice (self-escalate)
    """
    ag = AttackGraph()

    # Direct path: alice -> admin-role (1 hop, cost 0.15)
    ag.add_edge(AttackEdge(
        source_arn="alice",
        target_arn="admin-role",
        edge_type=EdgeType.CAN_ASSUME,
        detection_cost=0.15,
        success_probability=0.9,
        noise_level=NoiseLevel.LOW,
        guardrail_status="clear",
    ))

    # Indirect path: alice -> bob -> admin-role (2 hops, cost 0.10+0.15=0.25)
    ag.add_edge(AttackEdge(
        source_arn="alice",
        target_arn="bob",
        edge_type=EdgeType.CAN_CREATE_KEY,
        detection_cost=0.10,  # lower than direct assume
        success_probability=0.95,
        noise_level=NoiseLevel.LOW,
        guardrail_status="clear",
    ))

    ag.add_edge(AttackEdge(
        source_arn="bob",
        target_arn="admin-role",
        edge_type=EdgeType.CAN_ASSUME,
        detection_cost=0.15,
        success_probability=0.85,
        noise_level=NoiseLevel.LOW,
        guardrail_status="clear",
    ))

    return ag


def test_shortest_path():
    ag = _build_test_graph()
    pf = PathFinder(ag)
    path = pf.shortest_path("alice", "admin-role")
    assert path is not None
    assert path.hop_count == 1  # direct path is shortest
    assert path.nodes == ["alice", "admin-role"]


def test_quietest_path():
    ag = _build_test_graph()
    pf = PathFinder(ag)
    path = pf.quietest_path("alice", "admin-role")
    assert path is not None
    # Direct path cost=0.15 < indirect cost=0.25, so direct wins
    assert path.total_detection_cost == 0.15


def test_most_reliable_path():
    ag = _build_test_graph()
    pf = PathFinder(ag)
    path = pf.most_reliable_path("alice", "admin-role")
    assert path is not None
    assert path.total_success_probability > 0


def test_all_paths():
    ag = _build_test_graph()
    pf = PathFinder(ag)
    paths = pf.all_paths("alice", "admin-role")
    assert len(paths) == 2  # direct + indirect


def test_no_path():
    ag = AttackGraph()
    ag.add_edge(AttackEdge(
        source_arn="a", target_arn="b",
        edge_type=EdgeType.CAN_ASSUME,
        detection_cost=0.1,
        success_probability=0.9,
    ))
    pf = PathFinder(ag)
    path = pf.shortest_path("a", "c")
    assert path is None


def test_reachable_targets():
    ag = _build_test_graph()
    pf = PathFinder(ag)
    targets = pf.reachable_targets("alice")
    assert len(targets) >= 2  # bob + admin-role
    # Should be sorted by detection cost
    costs = [t["detection_cost"] for t in targets]
    assert costs == sorted(costs)


def test_score_path():
    ag = _build_test_graph()
    pf = PathFinder(ag)
    result = pf.score_path(["alice", "admin-role"], noise_budget=1.0)
    assert result["viable"] is True
    assert result["within_noise_budget"] is True
    assert result["detection_cost"] == 0.15
