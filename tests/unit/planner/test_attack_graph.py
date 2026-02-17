"""Tests for atlas.planner.attack_graph — AttackGraphBuilder."""

from atlas.core.graph import EnvironmentGraph
from atlas.core.models import LoggingState
from atlas.core.types import NodeType
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
    assert "Role Assumption" in summary["Attack Paths"]


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


def test_imds_credential_theft_targets_role(sample_graph_with_ec2, logging_state_active):
    """IMDS credential theft edge should target the instance profile's ROLE, not the instance."""
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph_with_ec2, scorer)
    ag = builder.build()

    alice_edges = ag.outgoing_edges("arn:aws:iam::123456789012:user/alice")
    imds_edges = [e for e in alice_edges if e.edge_type.value == "can_steal_imds_creds"]
    assert len(imds_edges) >= 1, "Alice (admin) should have IMDS theft edges"

    # The target should be a ROLE ARN, not the EC2 instance ARN
    for edge in imds_edges:
        assert ":role/" in edge.target_arn, (
            f"IMDS edge should target a role, got {edge.target_arn}"
        )
        assert ":instance/" not in edge.target_arn

    # The role should be derived from the instance profile name
    imds_edge = imds_edges[0]
    assert "my-ec2-role" in imds_edge.target_arn

    # The role node should exist in the graph (auto-created if needed)
    assert sample_graph_with_ec2.has_node(imds_edge.target_arn)


def test_imds_edge_creates_synthetic_role_node(sample_graph_with_ec2, logging_state_active):
    """When the role doesn't exist in the graph, a synthetic node is created."""
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph_with_ec2, scorer)
    ag = builder.build()

    role_arn = "arn:aws:iam::123456789012:role/my-ec2-role"
    assert sample_graph_with_ec2.has_node(role_arn)

    role_data = sample_graph_with_ec2.get_node_data(role_arn)
    assert role_data.get("discovered_via") == "instance_profile"
    assert role_data.get("role_name") == "my-ec2-role"


def test_ec2_attack_edges_with_admin_policy(sample_graph_with_ec2, logging_state_active):
    """Admin user should get volume snapshot and userdata injection edges."""
    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph_with_ec2, scorer)
    ag = builder.build()

    alice_edges = ag.outgoing_edges("arn:aws:iam::123456789012:user/alice")
    edge_types = {e.edge_type.value for e in alice_edges}

    # Alice has admin policy (*:*), so these should be present
    assert "can_snapshot_volume" in edge_types, "Should have volume snapshot edge"
    assert "can_modify_userdata" in edge_types, "Should have userdata injection edge"


def test_chain_finder_discovers_imds_chains(sample_graph_with_ec2, logging_state_active):
    """ChainFinder should find IMDS credential theft as an attack chain."""
    from atlas.planner.chain_finder import ChainFinder

    scorer = DetectionScorer(logging_state_active)
    builder = AttackGraphBuilder(sample_graph_with_ec2, scorer)
    ag = builder.build()

    finder = ChainFinder(ag, max_depth=4, max_chains=50)
    chains = finder.find_chains("arn:aws:iam::123456789012:user/alice")

    assert len(chains) > 0, "Should find at least one attack chain"

    # Check that IMDS credential theft is among the chains
    imds_chains = [
        c for c in chains
        if any(e.edge_type.value == "can_steal_imds_creds" for e in c.edges)
    ]
    assert len(imds_chains) >= 1, "Should find IMDS credential theft chain"
