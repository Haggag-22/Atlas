"""Shared test fixtures."""

import pytest

from atlas.core.config import AtlasConfig, AWSConfig, SafetyConfig, StealthConfig
from atlas.core.graph import EnvironmentGraph
from atlas.core.models import GuardrailState, LoggingState
from atlas.core.safety import SafetyGate
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import EdgeType, NodeType


@pytest.fixture
def config() -> AtlasConfig:
    """Default test configuration."""
    return AtlasConfig(
        aws=AWSConfig(region="us-east-1"),
        safety=SafetyConfig(
            allowed_account_ids=["123456789012"],
            allowed_regions=["us-east-1"],
            dry_run=True,
            max_noise_budget=10.0,
        ),
        stealth=StealthConfig(noise_budget=10.0),
    )


@pytest.fixture
def recorder() -> TelemetryRecorder:
    return TelemetryRecorder(correlation_id="test-correlation-001")


@pytest.fixture
def safety(config: AtlasConfig) -> SafetyGate:
    return SafetyGate(config.safety)


@pytest.fixture
def sample_graph() -> EnvironmentGraph:
    """Build a sample environment graph for testing.

    Structure:
      - 2 users: alice (admin-like), bob (limited)
      - 2 roles: admin-role, lambda-role
      - 1 group: developers (bob is member)
      - 3 policies: admin-policy, read-only, lambda-exec
      - Alice can assume admin-role
      - Bob has read-only policy
      - Lambda-role trusts lambda service
    """
    g = EnvironmentGraph()

    # Users
    g.add_node(
        "arn:aws:iam::123456789012:user/alice",
        NodeType.USER,
        data={
            "user_name": "alice",
            "user_id": "AIDAEXAMPLE1",
            "account_id": "123456789012",
            "access_key_ids": ["AKIAEXAMPLE1"],
            "attached_policy_arns": ["arn:aws:iam::123456789012:policy/admin-policy"],
            "inline_policy_names": [],
            "group_names": [],
            "permission_boundary_arn": None,
        },
        label="alice",
    )

    g.add_node(
        "arn:aws:iam::123456789012:user/bob",
        NodeType.USER,
        data={
            "user_name": "bob",
            "user_id": "AIDAEXAMPLE2",
            "account_id": "123456789012",
            "access_key_ids": [],
            "attached_policy_arns": [],
            "inline_policy_names": [],
            "group_names": ["developers"],
            "permission_boundary_arn": None,
        },
        label="bob",
    )

    # Roles
    g.add_node(
        "arn:aws:iam::123456789012:role/admin-role",
        NodeType.ROLE,
        data={
            "role_name": "admin-role",
            "role_id": "AROAEXAMPLE1",
            "account_id": "123456789012",
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                    "Action": "sts:AssumeRole",
                }],
            },
        },
        label="admin-role",
    )

    g.add_node(
        "arn:aws:iam::123456789012:role/lambda-role",
        NodeType.ROLE,
        data={
            "role_name": "lambda-role",
            "role_id": "AROAEXAMPLE2",
            "account_id": "123456789012",
            "trust_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            },
        },
        label="lambda-role",
    )

    # Group
    g.add_node(
        "arn:aws:iam::123456789012:group/developers",
        NodeType.GROUP,
        data={"group_name": "developers"},
        label="developers",
    )

    # Policies
    g.add_node(
        "arn:aws:iam::123456789012:policy/admin-policy",
        NodeType.POLICY,
        data={
            "policy_name": "admin-policy",
            "policy_document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }],
            },
        },
        label="admin-policy",
    )

    g.add_node(
        "arn:aws:iam::123456789012:policy/read-only",
        NodeType.POLICY,
        data={
            "policy_name": "read-only",
            "policy_document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "iam:List*",
                        "iam:Get*",
                        "s3:List*",
                        "s3:Get*",
                        "ec2:Describe*",
                    ],
                    "Resource": "*",
                }],
            },
        },
        label="read-only",
    )

    # Edges
    g.add_edge(
        "arn:aws:iam::123456789012:user/alice",
        "arn:aws:iam::123456789012:policy/admin-policy",
        EdgeType.HAS_POLICY,
    )

    g.add_edge(
        "arn:aws:iam::123456789012:user/bob",
        "arn:aws:iam::123456789012:group/developers",
        EdgeType.MEMBER_OF,
    )

    g.add_edge(
        "arn:aws:iam::123456789012:group/developers",
        "arn:aws:iam::123456789012:policy/read-only",
        EdgeType.HAS_POLICY,
    )

    # Trust edges
    g.add_edge(
        "arn:aws:iam::123456789012:user/alice",
        "arn:aws:iam::123456789012:role/admin-role",
        EdgeType.CAN_ASSUME,
        metadata={"trust_type": "same_account_specific"},
    )

    return g


@pytest.fixture
def sample_graph_with_ec2(sample_graph) -> EnvironmentGraph:
    """Extend sample_graph with an EC2 instance that has IMDSv1 + instance profile."""
    g = sample_graph

    # EC2 instance with IMDSv1 enabled and an instance profile
    g.add_node(
        "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456",
        NodeType.EC2_INSTANCE,
        data={
            "instance_id": "i-0abc123def456",
            "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456",
            "region": "us-east-1",
            "state": "running",
            "instance_profile_arn": "arn:aws:iam::123456789012:instance-profile/my-ec2-role",
            "public_ip": "54.1.2.3",
            "private_ip": "10.0.0.5",
            "security_group_ids": ["sg-abc123"],
            "subnet_id": "subnet-abc123",
            "vpc_id": "vpc-abc123",
            "user_data_available": False,
            "imds_v2_required": False,
            "tags": {"Name": "test-instance"},
        },
        label="i-0abc123def456",
    )

    return g


@pytest.fixture
def logging_state_active() -> LoggingState:
    """Active logging posture."""
    from atlas.core.models import CloudTrailConfig, GuardDutyConfig
    return LoggingState(
        cloudtrail_trails=[
            CloudTrailConfig(
                trail_name="main",
                trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
                is_logging=True,
                is_multi_region=True,
            )
        ],
        guardduty=GuardDutyConfig(
            detector_id="abc123",
            is_enabled=True,
            s3_protection=True,
        ),
        config_recorder_enabled=True,
        security_hub_enabled=True,
        access_analyzer_enabled=True,
    )


@pytest.fixture
def logging_state_minimal() -> LoggingState:
    """Minimal logging posture (CloudTrail off, no GuardDuty)."""
    return LoggingState()
