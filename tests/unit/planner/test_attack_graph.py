"""Tests for atlas.planner.attack_graph — AttackGraphBuilder."""

from atlas.core.graph import EnvironmentGraph
from atlas.core.models import LoggingState
from atlas.planner.attack_graph import AttackGraphBuilder
from atlas.planner.detection import DetectionScorer


def test_build_from_sample_graph(sample_graph, logging_state_active):
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph, scorer)
    ag = builder.build()

    # Should have at least the role assumption edge (alice -> admin-role)
    assert ag.edge_count > 0
    assert ag.node_count > 0

    summary = ag.summary()
    assert "can_assume" in summary["edge_types"]


def test_role_assumption_edges(sample_graph, logging_state_active):
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph, scorer)
    ag = builder.build()

    # Alice should be able to assume admin-role
    alice_edges = ag.outgoing_edges("arn:aws:iam::123456789012:user/alice")
    assume_edges = [e for e in alice_edges if e.edge_type.value == "can_assume"]
    assert len(assume_edges) >= 1

    admin_assumption = [e for e in assume_edges if "admin-role" in e.target_arn]
    assert len(admin_assumption) == 1
    assert admin_assumption[0].detection_cost > 0


def test_admin_policy_enables_privesc(sample_graph, logging_state_active):
    """Alice has admin policy (*:*), so she should have privesc edges."""
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph, scorer)
    ag = builder.build()

    alice_edges = ag.outgoing_edges("arn:aws:iam::123456789012:user/alice")
    edge_types = {e.edge_type.value for e in alice_edges}

    # Admin user should have key creation, policy attachment, etc.
    assert "can_create_key" in edge_types or "can_attach_policy" in edge_types


def test_detection_costs_are_positive(sample_graph, logging_state_active):
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph, scorer)
    ag = builder.build()

    for edge in ag.edges:
        assert edge.detection_cost >= 0.0
        assert 0.0 <= edge.success_probability <= 1.0
