"""
atlas.planner.attack_graph
~~~~~~~~~~~~~~~~~~~~~~~~~~
Transforms the EnvironmentModel into a weighted attack graph.

The attack graph is a *separate* graph from the environment graph.
Nodes are identities/resources.  Edges are *privilege transitions* —
actions an attacker can take to move from one identity/resource to another.

Each edge carries:
  - detection_cost (from DetectionScorer)
  - success_probability
  - required_permissions
  - guardrail_status

This is what the PathFinder operates on.
"""

from __future__ import annotations

import json
from typing import Any

import networkx as nx
import structlog

from atlas.core.graph import EnvironmentGraph
from atlas.core.models import AttackEdge
from atlas.core.permission_map import (
    PermissionConfidence,
    PermissionMap,
    _has_blocking_condition,
)
from atlas.core.types import EdgeType, NodeType, NoiseLevel
from atlas.planner.detection import DetectionScorer

logger = structlog.get_logger(__name__)


class AttackGraph:
    """Weighted directed graph of privilege transitions.

    Built from the EnvironmentModel by ``AttackGraphBuilder``.
    Consumed by ``PathFinder`` for path optimization.
    """

    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()
        self._edges: list[AttackEdge] = []

    def add_edge(self, edge: AttackEdge) -> None:
        """Add a privilege transition edge."""
        self._edges.append(edge)
        self._g.add_edge(
            edge.source_arn,
            edge.target_arn,
            edge_type=edge.edge_type.value,
            detection_cost=edge.detection_cost,
            success_probability=edge.success_probability,
            noise_level=edge.noise_level.value,
            guardrail_status=edge.guardrail_status,
            required_permissions=edge.required_permissions,
            api_actions=edge.api_actions,
            conditions=edge.conditions,
            notes=edge.notes,
        )

    @property
    def raw(self) -> nx.DiGraph:
        return self._g

    @property
    def edges(self) -> list[AttackEdge]:
        return list(self._edges)

    @property
    def node_count(self) -> int:
        return self._g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._g.number_of_edges()

    def has_node(self, arn: str) -> bool:
        return self._g.has_node(arn)

    def outgoing_edges(self, arn: str) -> list[AttackEdge]:
        """All attack edges originating from *arn*."""
        return [
            e for e in self._edges
            if e.source_arn == arn
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "edges": [e.model_dump() for e in self._edges],
            "node_count": self.node_count,
            "edge_count": self.edge_count,
        }

    def summary(self) -> dict[str, Any]:
        edge_types: dict[str, int] = {}
        _friendly_names = {
            "can_assume": "Role Assumption",
            "can_create_key": "Access Key Creation",
            "can_attach_policy": "Policy Attachment",
            "can_put_policy": "Inline Policy Injection",
            "can_passrole": "PassRole Abuse",
            "can_modify_trust": "Trust Policy Modification",
            "can_update_lambda": "Lambda Code Injection",
            "can_read_s3": "S3 Read Access",
            "can_write_s3": "S3 Write Access",
            "can_read_userdata": "EC2 User Data Disclosure",
            "can_enum_backup": "Backup Service Enumeration",
            "can_decode_key": "Access Key Account Decode",
            "can_loot_snapshot": "Public EBS Snapshot Loot",
            "can_steal_imds_creds": "IMDS Credential Theft",
            "can_ssm_session": "SSM Session / Command",
            "can_snapshot_volume": "EC2 Volume Snapshot Loot",
            "can_modify_userdata": "EC2 UserData Injection",
        }
        for e in self._edges:
            t = e.edge_type.value
            label = _friendly_names.get(t, t)
            edge_types[label] = edge_types.get(label, 0) + 1
        return {
            "Nodes": self.node_count,
            "Edges": self.edge_count,
            "Attack Paths": edge_types,
            "Avg Detection Cost": round(
                sum(e.detection_cost for e in self._edges) / len(self._edges), 4
            ) if self._edges else 0.0,
        }


class AttackGraphBuilder:
    """Builds an AttackGraph from the EnvironmentModel graph.

    This is where security knowledge gets encoded as graph edges.
    Each method below represents a *class of attack paths*.

    Permission checks go through the centralized PermissionMap
    (built by the PermissionResolverCollector).  When a PermissionMap
    is provided, it is the **single source of truth** for what each
    identity can do.  If no PermissionMap is available, the builder
    falls back to the legacy method of walking policy document edges
    in the environment graph.
    """

    def __init__(
        self,
        env_graph: EnvironmentGraph,
        scorer: DetectionScorer,
        permission_map: PermissionMap | None = None,
    ) -> None:
        self._env = env_graph
        self._scorer = scorer
        self._pmap = permission_map

    def build(self) -> AttackGraph:
        """Construct the full attack graph."""
        ag = AttackGraph()

        # Each method adds a category of attack edges
        self._add_role_assumption_edges(ag)
        self._add_access_key_creation_edges(ag)
        self._add_policy_attachment_edges(ag)
        self._add_inline_policy_edges(ag)
        self._add_passrole_edges(ag)
        self._add_trust_modification_edges(ag)
        self._add_lambda_privesc_edges(ag)
        self._add_s3_access_edges(ag)
        self._add_userdata_disclosure_edges(ag)
        self._add_backup_enumeration_edges(ag)
        self._add_key_account_decode_edges(ag)
        self._add_public_snapshot_edges(ag)
        self._add_imds_credential_theft_edges(ag)
        self._add_ssm_session_edges(ag)
        self._add_volume_snapshot_edges(ag)
        self._add_userdata_injection_edges(ag)

        logger.info("attack_graph_built", **ag.summary())
        return ag

    # ==================================================================
    # ATTACK PATH 1: Role Assumption (sts:AssumeRole)
    # ==================================================================
    def _add_role_assumption_edges(self, ag: AttackGraph) -> None:
        """Add role assumption edges based on BOTH trust policy AND permissions.

        AWS role assumption requires two things to be true:
          1. The role's trust policy must allow the caller (trust side)
          2. The caller must have sts:AssumeRole permission (permission side)

        The trust collector created CAN_ASSUME edges from trusted principals
        to roles. But when a role trusts the *account root*, that means any
        identity in the account with sts:AssumeRole can assume it. We need
        to expand those root-trust edges into real identity edges.
        """
        # Collect identities (users + roles)
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        # Build a set of (source, target) edges we've already added to avoid duplicates
        added: set[tuple[str, str]] = set()

        # --- Pass 1: Direct trust edges from the environment graph ---
        assume_edges = self._env.edges_of_type(EdgeType.CAN_ASSUME)
        for source, target, data in assume_edges:
            # Skip service principals and federated (can't be used by us directly)
            if source.startswith("service::") or source.startswith("federated::"):
                continue

            conditions = data.get("conditions", {})
            meta = data.get("metadata", {})
            prob, guardrail = self._evaluate_trust_conditions(conditions, meta)

            detection = self._scorer.score("sts:AssumeRole")
            trust_type = meta.get("trust_type", "")

            ag.add_edge(AttackEdge(
                source_arn=source,
                target_arn=target,
                edge_type=EdgeType.CAN_ASSUME,
                required_permissions=["sts:AssumeRole"],
                api_actions=["sts:AssumeRole"],
                detection_cost=detection,
                success_probability=prob,
                noise_level=self._scorer.get_noise_level("sts:AssumeRole"),
                guardrail_status=guardrail,
                conditions=conditions,
                notes=f"Role assumption via trust policy ({trust_type}).",
            ))
            added.add((source, target))

        # --- Pass 2: Expand account-root trust to real identities ---
        # When a role trusts "arn:aws:iam::ACCOUNT:root", any identity
        # in that account with sts:AssumeRole permission can assume it.
        for role_arn in roles:
            role_data = self._env.get_node_data(role_arn)
            trust_policy = role_data.get("trust_policy", {})
            if not trust_policy:
                continue

            # Check if this role trusts the account root
            trusts_root, root_conditions = self._role_trusts_account_root(trust_policy)
            if not trusts_root:
                continue

            # For each identity that has sts:AssumeRole permission, add an edge
            for identity in identities:
                if identity == role_arn:
                    continue
                if (identity, role_arn) in added:
                    continue

                if self._identity_has_permission(identity, "sts:AssumeRole"):
                    prob, guardrail = self._evaluate_trust_conditions(root_conditions, {"trust_type": "same_account_root"})
                    detection = self._scorer.score("sts:AssumeRole")

                    ag.add_edge(AttackEdge(
                        source_arn=identity,
                        target_arn=role_arn,
                        edge_type=EdgeType.CAN_ASSUME,
                        required_permissions=["sts:AssumeRole"],
                        api_actions=["sts:AssumeRole"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("sts:AssumeRole"),
                        guardrail_status=guardrail,
                        conditions=root_conditions,
                        notes="Role assumption — account root trust + sts:AssumeRole permission.",
                    ))
                    added.add((identity, role_arn))

    def _role_trusts_account_root(
        self, trust_policy: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Check if a trust policy trusts the account root (or wildcard *)."""
        for stmt in trust_policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            conditions = stmt.get("Condition", {})

            # Direct wildcard
            if principal == "*":
                return True, conditions

            if isinstance(principal, dict):
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if p == "*" or ":root" in p:
                        return True, conditions

        return False, {}

    def _evaluate_trust_conditions(
        self, conditions: dict[str, Any], meta: dict[str, Any],
    ) -> tuple[float, str]:
        """Evaluate trust conditions and return (probability, guardrail_status)."""
        prob = 1.0
        guardrail = "clear"

        if conditions:
            if self._has_mfa_condition(conditions):
                prob = 0.1
                guardrail = "blocked"
            elif self._has_external_id_condition(conditions):
                prob = 0.2
                guardrail = "uncertain"
            elif self._has_source_ip_condition(conditions):
                prob = 0.3
                guardrail = "uncertain"
            else:
                prob = 0.8

        trust_type = meta.get("trust_type", "")
        if trust_type == "wildcard":
            prob = 0.95
            guardrail = "clear"
        elif trust_type == "same_account_root":
            prob = 0.95
            guardrail = "clear"

        return prob, guardrail

    # ==================================================================
    # ATTACK PATH 2: Access Key Creation (iam:CreateAccessKey)
    # ==================================================================
    def _add_access_key_creation_edges(self, ag: AttackGraph) -> None:
        """If identity A has iam:CreateAccessKey on user B, add edge.

        FP-2: Permission check is scoped to the TARGET user's ARN.
        Policies like "Resource: arn:aws:iam::*:user/${aws:username}"
        only allow self-key-creation, which the PermissionMap will
        correctly reject for cross-user targets.
        """
        users = self._env.nodes_of_type(NodeType.USER)
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for source in identities:
            for target_user in users:
                if source == target_user:
                    continue
                # FP-2: Resource-scoped check
                if not self._identity_has_permission(
                    source, "iam:CreateAccessKey", resource_arn=target_user,
                ):
                    continue
                detection = self._scorer.score("iam:CreateAccessKey")
                prob = 0.9 * self._get_permission_confidence_multiplier(
                    source, "iam:CreateAccessKey", target_user,
                )
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=target_user,
                    edge_type=EdgeType.CAN_CREATE_KEY,
                    required_permissions=["iam:CreateAccessKey"],
                    api_actions=["iam:CreateAccessKey"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=self._scorer.get_noise_level("iam:CreateAccessKey"),
                    guardrail_status="clear",
                    notes="Create access key for target user — credential harvesting.",
                ))

    # ==================================================================
    # ATTACK PATH 3: Policy Attachment (iam:AttachUserPolicy / AttachRolePolicy)
    # ==================================================================
    def _add_policy_attachment_edges(self, ag: AttackGraph) -> None:
        """If identity A can attach policies to target B, add edge.

        FP-2: Resource-scoped — policies often restrict attachment to
        specific ARN patterns (e.g., only to roles with a specific path).
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for source in identities:
            # Can attach to users
            for target in self._env.nodes_of_type(NodeType.USER):
                if self._identity_has_permission(
                    source, "iam:AttachUserPolicy", resource_arn=target,
                ):
                    detection = self._scorer.score("iam:AttachUserPolicy")
                    prob = 0.9 * self._get_permission_confidence_multiplier(
                        source, "iam:AttachUserPolicy", target,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_ATTACH_POLICY,
                        required_permissions=["iam:AttachUserPolicy"],
                        api_actions=["iam:AttachUserPolicy"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("iam:AttachUserPolicy"),
                        guardrail_status="clear",
                        notes="Attach managed policy to user — direct privesc.",
                    ))

            # Can attach to roles
            for target in self._env.nodes_of_type(NodeType.ROLE):
                if self._identity_has_permission(
                    source, "iam:AttachRolePolicy", resource_arn=target,
                ):
                    detection = self._scorer.score("iam:AttachRolePolicy")
                    prob = 0.85 * self._get_permission_confidence_multiplier(
                        source, "iam:AttachRolePolicy", target,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_ATTACH_POLICY,
                        required_permissions=["iam:AttachRolePolicy"],
                        api_actions=["iam:AttachRolePolicy"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("iam:AttachRolePolicy"),
                        guardrail_status="clear",
                        notes="Attach managed policy to role — escalation via role.",
                    ))

    # ==================================================================
    # ATTACK PATH 4: Inline Policy Creation (iam:PutUserPolicy / PutRolePolicy)
    # ==================================================================
    def _add_inline_policy_edges(self, ag: AttackGraph) -> None:
        """Inject arbitrary inline policies on users/roles.

        FP-2: Resource-scoped to target identity ARN.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for source in identities:
            for target in self._env.nodes_of_type(NodeType.USER):
                if self._identity_has_permission(
                    source, "iam:PutUserPolicy", resource_arn=target,
                ):
                    detection = self._scorer.score("iam:PutUserPolicy")
                    prob = 0.9 * self._get_permission_confidence_multiplier(
                        source, "iam:PutUserPolicy", target,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_PUT_POLICY,
                        required_permissions=["iam:PutUserPolicy"],
                        api_actions=["iam:PutUserPolicy"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("iam:PutUserPolicy"),
                        guardrail_status="clear",
                        notes="Create inline policy on user — stealthier than managed policy (no ARN).",
                    ))

            for target in self._env.nodes_of_type(NodeType.ROLE):
                if self._identity_has_permission(
                    source, "iam:PutRolePolicy", resource_arn=target,
                ):
                    detection = self._scorer.score("iam:PutRolePolicy")
                    prob = 0.85 * self._get_permission_confidence_multiplier(
                        source, "iam:PutRolePolicy", target,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_PUT_POLICY,
                        required_permissions=["iam:PutRolePolicy"],
                        api_actions=["iam:PutRolePolicy"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("iam:PutRolePolicy"),
                        guardrail_status="clear",
                        notes="Create inline policy on role — privesc via role permissions.",
                    ))

    # ==================================================================
    # ATTACK PATH 5: PassRole Abuse (iam:PassRole + service create)
    # ==================================================================
    def _add_passrole_edges(self, ag: AttackGraph) -> None:
        """PassRole + Lambda/EC2 create = assume any role the service can use.

        FP-2: PassRole is commonly restricted to specific role ARNs.
        The resource_arn check ensures we only add edges for roles
        the identity is actually allowed to pass.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        for source in identities:
            has_create_lambda = self._identity_has_permission(source, "lambda:CreateFunction")
            has_update_lambda = self._identity_has_permission(source, "lambda:UpdateFunctionCode")

            if not (has_create_lambda or has_update_lambda):
                continue

            for role in roles:
                # FP-2: Check PassRole scoped to the specific role ARN
                if not self._identity_has_permission(
                    source, "iam:PassRole", resource_arn=role,
                ):
                    continue
                api = "lambda:CreateFunction" if has_create_lambda else "lambda:UpdateFunctionCode"
                detection = (
                    self._scorer.score("iam:PassRole")
                    + self._scorer.score(api)
                )
                prob = 0.75 * self._get_permission_confidence_multiplier(
                    source, "iam:PassRole", role,
                )
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role,
                    edge_type=EdgeType.CAN_PASSROLE,
                    required_permissions=["iam:PassRole", api],
                    api_actions=["iam:PassRole", api],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes=f"PassRole + {api} — indirect privesc to target role via Lambda.",
                ))

    # ==================================================================
    # ATTACK PATH 6: Trust Policy Modification (iam:UpdateAssumeRolePolicy)
    # ==================================================================
    def _add_trust_modification_edges(self, ag: AttackGraph) -> None:
        """Modify a role's trust policy to allow our identity to assume it.

        FP-2: Resource-scoped to target role ARN.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        for source in identities:
            for target in roles:
                if not self._identity_has_permission(
                    source, "iam:UpdateAssumeRolePolicy", resource_arn=target,
                ):
                    continue
                detection = self._scorer.score("iam:UpdateAssumeRolePolicy")
                prob = 0.9 * self._get_permission_confidence_multiplier(
                    source, "iam:UpdateAssumeRolePolicy", target,
                )
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=target,
                    edge_type=EdgeType.CAN_MODIFY_TRUST,
                    required_permissions=["iam:UpdateAssumeRolePolicy"],
                    api_actions=["iam:UpdateAssumeRolePolicy"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.CRITICAL,
                    guardrail_status="clear",
                    notes="Modify trust policy — backdoor persistent role access. VERY HIGH NOISE.",
                ))

    # ==================================================================
    # ATTACK PATH 7: Lambda Code Injection
    # ==================================================================
    def _add_lambda_privesc_edges(self, ag: AttackGraph) -> None:
        """Update Lambda function code to steal execution role credentials.

        FP-2: Permission scoped to the specific Lambda function ARN.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        lambdas = self._env.nodes_of_type(NodeType.LAMBDA_FUNCTION)

        for source in identities:
            for func_arn in lambdas:
                # FP-2: Check against the specific function ARN
                if not self._identity_has_permission(
                    source, "lambda:UpdateFunctionCode", resource_arn=func_arn,
                ):
                    continue
                func_data = self._env.get_node_data(func_arn)
                role_arn = func_data.get("role_arn")
                if not role_arn:
                    continue

                detection = self._scorer.score("lambda:UpdateFunctionCode")
                prob = 0.80 * self._get_permission_confidence_multiplier(
                    source, "lambda:UpdateFunctionCode", func_arn,
                )
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role_arn,
                    edge_type=EdgeType.CAN_UPDATE_LAMBDA,
                    required_permissions=["lambda:UpdateFunctionCode"],
                    api_actions=["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes=f"Inject code into {func_arn} to steal role {role_arn} credentials.",
                ))

    # ==================================================================
    # ATTACK PATH 8: S3 Bucket Access (read / write)
    # ==================================================================
    def _add_s3_access_edges(self, ag: AttackGraph) -> None:
        """Add S3 access edges based on IAM permissions + bucket policies.

        Two edge types:
          - CAN_READ_S3:  identity has s3:GetObject / s3:ListBucket
          - CAN_WRITE_S3: identity has s3:PutObject / s3:DeleteObject / s3:PutBucketPolicy
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        buckets = self._env.nodes_of_type(NodeType.S3_BUCKET)

        # S3 read permissions (common read actions)
        s3_read_actions = ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"]
        # S3 write permissions (dangerous write actions)
        s3_write_actions = ["s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"]

        for bucket_arn in buckets:
            bucket_data = self._env.get_node_data(bucket_arn)
            bucket_policy = bucket_data.get("bucket_policy")
            bucket_name = bucket_data.get("name", bucket_arn.split(":::")[-1])

            for source in identities:
                # FP-2: Check IAM-based access scoped to bucket ARN
                has_read = any(
                    self._identity_has_permission(
                        source, a, resource_arn=bucket_arn,
                    ) for a in s3_read_actions
                )
                has_write = any(
                    self._identity_has_permission(
                        source, a, resource_arn=bucket_arn,
                    ) for a in s3_write_actions
                )

                # --- Check bucket-policy-based access ---
                if bucket_policy and not has_read:
                    has_read = self._bucket_policy_allows(
                        bucket_policy, source, s3_read_actions,
                    )
                if bucket_policy and not has_write:
                    has_write = self._bucket_policy_allows(
                        bucket_policy, source, s3_write_actions,
                    )

                if has_write:
                    detection = self._scorer.score("s3:PutObject")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=bucket_arn,
                        edge_type=EdgeType.CAN_WRITE_S3,
                        required_permissions=["s3:PutObject"],
                        api_actions=["s3:PutObject", "s3:PutBucketPolicy"],
                        detection_cost=detection,
                        success_probability=0.90,
                        noise_level=self._scorer.get_noise_level("s3:PutObject") if detection < 0.5 else NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        notes=f"Write access to S3 bucket '{bucket_name}'.",
                    ))
                elif has_read:
                    detection = self._scorer.score("s3:GetObject")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=bucket_arn,
                        edge_type=EdgeType.CAN_READ_S3,
                        required_permissions=["s3:GetObject"],
                        api_actions=["s3:GetObject", "s3:ListBucket"],
                        detection_cost=detection,
                        success_probability=0.95,
                        noise_level=self._scorer.get_noise_level("s3:GetObject") if detection < 0.3 else NoiseLevel.LOW,
                        guardrail_status="clear",
                        notes=f"Read access to S3 bucket '{bucket_name}'.",
                    ))

    # ==================================================================
    # ATTACK PATH 9: EC2 User Data Disclosure
    # ==================================================================
    def _add_userdata_disclosure_edges(self, ag: AttackGraph) -> None:
        """Add edges for EC2 user data disclosure via the API.

        If an identity has ec2:DescribeInstanceAttribute permission, they
        can retrieve user data from EC2 instances.  User data frequently
        contains hardcoded credentials, API keys, database passwords,
        internal service URLs, and bootstrap configuration that was
        written once at launch time and forgotten.

        Two attack scenarios exist:
          1. API-based (modeled here): identity calls
             ec2:DescribeInstanceAttribute with attribute=userData.
             This is a CloudTrail management-read event with low noise.
          2. IMDS-based (noted, not modeled): attacker with shell access
             on the instance queries http://169.254.169.254/latest/user-data/.
             No IAM permissions required — just local access.  IMDSv1
             instances are additionally vulnerable to SSRF-based extraction.

        Edges target instances where user_data_available is True (confirmed
        during recon) or where it is unknown (conservative: assume present).
        Instances with IMDSv1 get higher success probability because they
        are also vulnerable to SSRF-based metadata extraction.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        instances = self._env.nodes_of_type(NodeType.EC2_INSTANCE)

        for source in identities:
            if not self._identity_has_permission(
                source, "ec2:DescribeInstanceAttribute",
            ):
                continue

            for inst_arn in instances:
                inst_data = self._env.get_node_data(inst_arn)

                # Only add edges for instances that have user data or
                # where presence is unknown (conservative assumption)
                has_userdata = inst_data.get("user_data_available", False)
                if not has_userdata:
                    continue

                instance_id = inst_data.get(
                    "instance_id", inst_arn.split("/")[-1]
                )
                imds_v2_required = inst_data.get("imds_v2_required", True)

                # Base detection cost from the API profile
                detection = self._scorer.score(
                    "ec2:DescribeInstanceAttribute"
                )

                # Success probability: higher if user data exists and
                # IMDSv1 is enabled (additional SSRF attack surface)
                prob = 0.85
                imds_note = ""
                if not imds_v2_required:
                    prob = 0.95
                    imds_note = (
                        " IMDSv1 enabled — also vulnerable to SSRF-based "
                        "metadata/user-data extraction without API calls."
                    )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=inst_arn,
                    edge_type=EdgeType.CAN_READ_USERDATA,
                    required_permissions=["ec2:DescribeInstanceAttribute"],
                    api_actions=["ec2:DescribeInstanceAttribute"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=self._scorer.get_noise_level(
                        "ec2:DescribeInstanceAttribute"
                    ),
                    guardrail_status="clear",
                    conditions={
                        "user_data_available": True,
                        "imds_v2_required": imds_v2_required,
                    },
                    notes=(
                        f"EC2 User Data Disclosure — retrieve user data "
                        f"from instance {instance_id} via API. User data "
                        f"frequently contains hardcoded credentials, API "
                        f"keys, database passwords, and bootstrap config "
                        f"written at launch time.{imds_note}"
                    ),
                ))

    # ==================================================================
    # ATTACK PATH 10: AWS Backup Service Enumeration
    # ==================================================================
    def _add_backup_enumeration_edges(self, ag: AttackGraph) -> None:
        """Add edges for Living-off-the-Cloud recon via AWS Backup APIs.

        An attacker with backup:ListProtectedResources or backup:List*
        permissions can use the AWS Backup control plane to discover
        critical production resources, naming conventions, tagging
        strategies, backup schedules, and retention policies — all
        without calling traditional, heavily-monitored service-level
        enumeration APIs like ec2:DescribeInstances or
        rds:DescribeDBInstances.

        AWS Backup acts as a curated index of what actually matters in
        the account.  Resources that are backed up are confirmed high-
        value targets.  This technique produces high intelligence value
        with minimal noise.

        Edges are added from each identity with Backup permissions to
        the account root node (this is account-level recon) and to each
        backup plan node (for operational timing intelligence).
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        account_nodes = self._env.nodes_of_type(NodeType.ACCOUNT)
        backup_plans = self._env.nodes_of_type(NodeType.BACKUP_PLAN)

        # The key permission — one call reveals all backed-up resources
        primary_action = "backup:ListProtectedResources"

        for source in identities:
            has_list_protected = self._identity_has_permission(
                source, primary_action,
            )
            has_list_plans = self._identity_has_permission(
                source, "backup:ListBackupPlans",
            )

            if not (has_list_protected or has_list_plans):
                continue

            # Aggregate detection cost across the Backup API call chain
            api_actions = []
            total_detection = 0.0
            if has_list_protected:
                api_actions.append("backup:ListProtectedResources")
                total_detection += self._scorer.score(
                    "backup:ListProtectedResources"
                )
            if has_list_plans:
                api_actions.extend([
                    "backup:ListBackupPlans",
                    "backup:GetBackupPlan",
                    "backup:ListBackupSelections",
                    "backup:GetBackupSelection",
                ])
                total_detection += self._scorer.score(
                    "backup:ListBackupPlans"
                )
                total_detection += self._scorer.score(
                    "backup:GetBackupPlan"
                )

            required = [a for a in api_actions[:1]]  # primary permission

            # Edge to account node: account-level resource discovery
            for account_arn in account_nodes:
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=account_arn,
                    edge_type=EdgeType.CAN_ENUM_BACKUP,
                    required_permissions=required,
                    api_actions=api_actions,
                    detection_cost=total_detection,
                    success_probability=0.90,
                    noise_level=self._scorer.get_noise_level(
                        primary_action
                        if has_list_protected
                        else "backup:ListBackupPlans"
                    ),
                    guardrail_status="clear",
                    notes=(
                        "AWS Backup enumeration — Living-off-the-Cloud "
                        "recon that discovers critical production "
                        "resources, naming conventions, and operational "
                        "timing via low-signal Backup control-plane "
                        "APIs instead of traditional, heavily-monitored "
                        "service-level enumeration commands."
                    ),
                ))

            # Edges to backup plan nodes: timing & targeting intel
            if has_list_plans:
                for plan_arn in backup_plans:
                    plan_data = self._env.get_node_data(plan_arn)
                    plan_name = plan_data.get(
                        "plan_name", plan_arn.split(":")[-1]
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=plan_arn,
                        edge_type=EdgeType.CAN_ENUM_BACKUP,
                        required_permissions=[
                            "backup:ListBackupPlans",
                            "backup:GetBackupPlan",
                        ],
                        api_actions=[
                            "backup:GetBackupPlan",
                            "backup:ListBackupSelections",
                            "backup:GetBackupSelection",
                        ],
                        detection_cost=self._scorer.score(
                            "backup:GetBackupPlan"
                        ),
                        success_probability=0.90,
                        noise_level=self._scorer.get_noise_level(
                            "backup:GetBackupPlan"
                        ),
                        guardrail_status="clear",
                        notes=(
                            f"Enumerate backup plan '{plan_name}' for "
                            f"schedule timing, retention policies, "
                            f"target resource ARNs, tagging strategies, "
                            f"and the IAM role used by the Backup "
                            f"service."
                        ),
                    ))

    # ==================================================================
    # ATTACK PATH 10: Access Key Account ID Decoding
    # ==================================================================
    def _add_key_account_decode_edges(self, ag: AttackGraph) -> None:
        """Add edges for the Get-Account-ID-from-Access-Key technique.

        This technique works at TWO levels:

        **Level 1 — Offline decoding (silent, zero API calls):**
        The AWS account ID is encoded directly in the access key ID
        itself.  By base32-decoding characters 5-12 of the key ID and
        applying a bit mask, the 12-digit account ID can be extracted.
        This requires ZERO API calls, generates ZERO CloudTrail events,
        and is completely invisible to both the target and the caller.
        Works for keys created after March 29, 2019.

        **Level 2 — API-based (sts:GetAccessKeyInfo):**
        For old-format keys (pre-2019) or to validate results, the
        sts:GetAccessKeyInfo API can resolve the account ID.  This
        call is logged ONLY in the CALLER's account, NOT in the
        target's account — making it operationally safe for red teams.

        Research credit:
          - Aidan Steele: AWS Access Key ID Formats
          - Tal Be'ery: A short note on AWS KEY ID

        Edges are added from identities to credential nodes where:
          - The identity can see access keys (iam:ListAccessKeys)
          - Or the identity has sts:GetAccessKeyInfo permission
        Offline decoding is always modeled as available (no API needed).
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        credentials = self._env.nodes_of_type(NodeType.CREDENTIAL)

        if not credentials:
            return

        for source in identities:
            # Check for sts:GetAccessKeyInfo (API-based decoding)
            has_get_key_info = self._identity_has_permission(
                source, "sts:GetAccessKeyInfo",
            )
            # Check for iam:ListAccessKeys (can discover keys, then decode offline)
            has_list_keys = self._identity_has_permission(
                source, "iam:ListAccessKeys",
            )

            if not (has_get_key_info or has_list_keys):
                continue

            for cred_arn in credentials:
                cred_data = self._env.get_node_data(cred_arn)
                if not cred_data:
                    continue

                ak_id = cred_data.get("access_key_id", "")
                decoded_account = cred_data.get("decoded_account_id")
                is_cross_account = cred_data.get("is_cross_account", False)

                # Determine detection cost:
                # - Offline decode: zero detection (no API call)
                # - API decode: very low (only in caller's account)
                if decoded_account:
                    # Key was already decoded offline — zero noise
                    detection_cost = 0.0
                    noise = NoiseLevel.SILENT
                    api_actions = []
                    method_note = "OFFLINE DECODE (zero API calls)"
                else:
                    # Need the API — but it only logs in caller's account
                    detection_cost = self._scorer.score(
                        "sts:GetAccessKeyInfo"
                    )
                    noise = self._scorer.get_noise_level(
                        "sts:GetAccessKeyInfo"
                    )
                    api_actions = ["sts:GetAccessKeyInfo"]
                    method_note = "API DECODE (logs only in caller's account)"

                notes_parts = [
                    f"Access Key Account ID Decode via {method_note}.",
                ]
                if decoded_account:
                    notes_parts.append(
                        f"Key {ak_id[:8]}... resolves to account "
                        f"{decoded_account}."
                    )
                if is_cross_account:
                    notes_parts.append(
                        "CROSS-ACCOUNT: This key's encoded account ID "
                        "differs from the owner's account. May indicate "
                        "an external credential, a key from a different "
                        "account, or scope boundary."
                    )

                # Success probability: offline decode is deterministic
                success_prob = 1.0 if decoded_account else 0.85

                required_permissions = (
                    ["sts:GetAccessKeyInfo"]
                    if has_get_key_info
                    else ["iam:ListAccessKeys"]
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=cred_arn,
                    edge_type=EdgeType.CAN_DECODE_KEY,
                    required_permissions=required_permissions,
                    api_actions=api_actions,
                    detection_cost=detection_cost,
                    success_probability=success_prob,
                    noise_level=noise,
                    guardrail_status="clear",
                    notes=" ".join(notes_parts),
                ))

    # ==================================================================
    # ATTACK PATH 11: Public EBS Snapshot Looting
    # ==================================================================
    def _add_public_snapshot_edges(self, ag: AttackGraph) -> None:
        """Add edges for looting publicly exposed EBS snapshots.

        Public EBS snapshots are a unique attack surface in AWS:

        - **Discovery is free:** Any AWS account can call
          ``ec2:DescribeSnapshots --restorable-by-user-ids all --owner-ids
          <account_id>`` to find all public snapshots belonging to the target.
        - **Logs only in caller's account:** The DescribeSnapshots call logs
          in the CALLER's CloudTrail, NOT the victim's.
        - **No access controls:** If a snapshot is public, there are NO
          resource-based policies — anyone can clone it.
        - **Full data access:** An attacker creates an EBS volume from the
          snapshot in their own account, attaches it to an EC2 instance,
          and mounts it to read the entire filesystem.

        Commonly exposed data: credentials, source code, database dumps,
        configuration files, SSH keys, certificates, application secrets.

        This technique is often chained after key-account-ID decoding:
        discover account ID from access key -> check for public snapshots.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        snapshots = self._env.nodes_of_type(NodeType.EBS_SNAPSHOT)

        if not snapshots:
            return

        for source in identities:
            # Any identity with ec2:DescribeSnapshots can find these
            # (and technically any AWS account can, even external ones)
            has_describe = self._identity_has_permission(
                source, "ec2:DescribeSnapshots",
            )
            # ec2:CreateVolume needed to actually loot the snapshot
            has_create_vol = self._identity_has_permission(
                source, "ec2:CreateVolume",
            )

            if not has_describe:
                continue

            for snap_arn in snapshots:
                snap_data = self._env.get_node_data(snap_arn)
                if not snap_data:
                    continue

                snap_id = snap_data.get("snapshot_id", snap_arn.split("/")[-1])
                encrypted = snap_data.get("encrypted", False)
                volume_size = snap_data.get("volume_size_gb", 0)
                description = snap_data.get("description", "")

                # Detection: DescribeSnapshots is read-only, low noise,
                # and only logs in the caller's account
                detection_cost = self._scorer.score("ec2:DescribeSnapshots")

                # Success probability depends on encryption and permissions
                if encrypted:
                    # Encrypted snapshots need the KMS key to create a volume
                    # from them — much harder to loot unless you have the key
                    success_prob = 0.20
                    encryption_note = (
                        "This snapshot is ENCRYPTED. Looting requires access "
                        "to the KMS key used for encryption, which significantly "
                        "reduces exploitability."
                    )
                elif has_create_vol:
                    # Unencrypted + can create volume = full loot capability
                    success_prob = 0.95
                    encryption_note = (
                        "This snapshot is NOT encrypted. Any account can create "
                        "a volume from it and mount it for full filesystem access."
                    )
                else:
                    # Can discover but not yet loot (need CreateVolume)
                    success_prob = 0.60
                    encryption_note = (
                        "Discovery confirmed but ec2:CreateVolume permission "
                        "is needed to clone and mount the snapshot."
                    )

                notes = (
                    f"Public EBS Snapshot {snap_id} "
                    f"({volume_size} GiB) is exposed. "
                    f"{encryption_note}"
                )
                if description:
                    notes += (
                        f" Snapshot description: '{description[:100]}'"
                    )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=snap_arn,
                    edge_type=EdgeType.CAN_LOOT_SNAPSHOT,
                    required_permissions=["ec2:DescribeSnapshots"],
                    api_actions=[
                        "ec2:DescribeSnapshots",
                        "ec2:CreateVolume",
                    ],
                    detection_cost=detection_cost,
                    success_probability=success_prob,
                    noise_level=self._scorer.get_noise_level(
                        "ec2:DescribeSnapshots"
                    ),
                    guardrail_status="clear",
                    notes=notes,
                ))

    @staticmethod
    def _bucket_policy_allows(
        policy: dict[str, Any],
        identity_arn: str,
        actions: list[str],
    ) -> bool:
        """Check if a bucket policy grants specific actions to the identity."""
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            # Check principal match
            principal = stmt.get("Principal", {})
            if not _principal_matches(principal, identity_arn):
                continue

            # Check action match
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]

            for needed in actions:
                for sa in stmt_actions:
                    if sa == "*" or sa == needed:
                        return True
                    if sa.endswith("*") and needed.startswith(sa[:-1]):
                        return True
        return False

    # ==================================================================
    # Permission checking helper
    # ==================================================================
    def _identity_has_permission(
        self,
        identity_arn: str,
        action: str,
        resource_arn: str = "*",
    ) -> bool:
        """Check if an identity has a specific IAM permission.

        Uses the centralized PermissionMap when available (preferred).
        The PermissionMap implements full IAM evaluation logic:
          - Explicit Deny (always wins)
          - SCP enforcement
          - Permission boundary intersection
          - Session policy intersection (assumed roles)
          - Identity policy Allow
          - Resource-based policy grants
          - NotAction/NotResource
          - Condition key awareness

        Falls back to legacy policy-document walking when the
        PermissionMap has no data for this identity.
        """
        # ── Primary: Use the PermissionMap ─────────────────────────────
        if self._pmap is not None:
            result = self._pmap.identity_has_permission(
                identity_arn, action, resource_arn,
            )
            if result:
                return True
            # If the PermissionMap has a profile but says no, trust it
            profile = self._pmap.get_profile(identity_arn)
            if profile and profile.policy_documents_available:
                return False
            # If no profile or no policy docs, fall through to legacy

        # ── Fallback: Legacy policy-document walking ───────────────────
        return self._legacy_permission_check(identity_arn, action)

    def _get_permission_confidence_multiplier(
        self,
        identity_arn: str,
        action: str,
        resource_arn: str = "*",
    ) -> float:
        """Get success probability multiplier based on permission confidence.

        Returns 1.0 for confirmed permissions, lower values for inferred
        or condition-gated permissions.
        """
        if self._pmap is not None:
            return self._pmap.get_confidence_multiplier(
                identity_arn, action, resource_arn,
            )
        return 1.0  # Legacy: assume confirmed if policy doc says yes

    def _legacy_permission_check(
        self, identity_arn: str, action: str,
    ) -> bool:
        """Legacy permission check: walk policy edges in the environment graph.

        Used as fallback when the PermissionMap has no data for an identity.

        FP-6: Now checks for explicit Deny BEFORE returning True from
        any Allow match.  This prevents false positives where a policy
        explicitly denies an action that another policy allows.
        """
        outgoing = self._env.outgoing(identity_arn)

        # FP-6: First pass — check for explicit Deny in all policies
        for target_arn, edge_data in outgoing:
            edge_type = edge_data.get("edge_type", "")
            if edge_type in (EdgeType.HAS_POLICY.value, EdgeType.HAS_INLINE_POLICY.value):
                policy_data = self._env.get_node_data(target_arn)
                doc = policy_data.get("policy_document", {})
                if self._policy_denies_action(doc, action):
                    return False

        # Also check group policies for deny
        for target_arn, edge_data in outgoing:
            if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                for policy_arn, pedge in self._env.outgoing(target_arn):
                    if pedge.get("edge_type") in (EdgeType.HAS_POLICY.value, EdgeType.HAS_INLINE_POLICY.value):
                        policy_data = self._env.get_node_data(policy_arn)
                        doc = policy_data.get("policy_document", {})
                        if self._policy_denies_action(doc, action):
                            return False

        # Second pass — check for Allow
        for target_arn, edge_data in outgoing:
            edge_type = edge_data.get("edge_type", "")
            if edge_type in (EdgeType.HAS_POLICY.value, EdgeType.HAS_INLINE_POLICY.value):
                if self._is_admin_policy_arn(target_arn):
                    return True
                policy_data = self._env.get_node_data(target_arn)
                doc = policy_data.get("policy_document", {})
                if self._policy_allows_action(doc, action):
                    return True

        # Check group memberships for allow
        for target_arn, edge_data in outgoing:
            if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                group_outgoing = self._env.outgoing(target_arn)
                for policy_arn, pedge in group_outgoing:
                    if pedge.get("edge_type") in (EdgeType.HAS_POLICY.value, EdgeType.HAS_INLINE_POLICY.value):
                        if self._is_admin_policy_arn(policy_arn):
                            return True
                        policy_data = self._env.get_node_data(policy_arn)
                        doc = policy_data.get("policy_document", {})
                        if self._policy_allows_action(doc, action):
                            return True

        return False

    @staticmethod
    def _is_admin_policy_arn(arn: str) -> bool:
        """Recognize AWS-managed policies that grant full or near-full access."""
        admin_policies = {
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
        }
        return arn in admin_policies

    @staticmethod
    def _policy_allows_action(doc: dict[str, Any], action: str) -> bool:
        """Check if a policy document allows a specific action.

        FP-3: Skips Allow statements with blocking conditions (MFA, IP).
        """
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            # FP-3: Skip condition-gated allows that attacker can't satisfy
            conditions = stmt.get("Condition", {})
            if _has_blocking_condition(conditions):
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if a == "*" or a == action:
                    return True
                if a.endswith("*"):
                    prefix = a[:-1]
                    if action.startswith(prefix):
                        return True
        return False

    @staticmethod
    def _policy_denies_action(doc: dict[str, Any], action: str) -> bool:
        """FP-6: Check if a policy document explicitly denies an action."""
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Deny":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if a == "*" or a == action:
                    return True
                if a.endswith("*"):
                    prefix = a[:-1]
                    if action.startswith(prefix):
                        return True
        return False

    @staticmethod
    def _has_mfa_condition(conditions: dict[str, Any]) -> bool:
        for op, values in conditions.items():
            if isinstance(values, dict):
                for key in values:
                    if "MultiFactorAuth" in key:
                        return True
        return False

    @staticmethod
    def _has_external_id_condition(conditions: dict[str, Any]) -> bool:
        for op, values in conditions.items():
            if isinstance(values, dict):
                for key in values:
                    if "ExternalId" in key:
                        return True
        return False

    @staticmethod
    def _has_source_ip_condition(conditions: dict[str, Any]) -> bool:
        for op, values in conditions.items():
            if isinstance(values, dict):
                for key in values:
                    if "SourceIp" in key:
                        return True
        return False

    # ==================================================================
    # ATTACK PATH 13: IMDS Credential Theft (IMDSv1 → steal role creds)
    # ==================================================================
    def _add_imds_credential_theft_edges(self, ag: AttackGraph) -> None:
        """Add edges for IMDS-based credential theft from EC2 instances.

        EC2 instances with **IMDSv1 enabled** and an **instance profile**
        (IAM role) are vulnerable to credential theft via the Instance
        Metadata Service.  An attacker who can reach the instance
        (via SSRF, shell, or SSM) can query
        ``http://169.254.169.254/latest/meta-data/iam/security-credentials/``
        to obtain temporary credentials for the instance's role.

        This edge is created when:
          1. The instance has IMDSv1 enabled (imds_v2_required == False)
          2. The instance has an instance profile (role attached)
          3. The caller has ec2:DescribeInstances (knows the target exists)

        The edge goes from the caller identity to the instance profile's
        role, representing lateral movement via credential theft.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        instances = self._env.nodes_of_type(NodeType.EC2_INSTANCE)

        for source in identities:
            if not self._identity_has_permission(
                source, "ec2:DescribeInstances",
            ):
                continue

            for inst_arn in instances:
                inst_data = self._env.get_node_data(inst_arn)
                imds_v2_required = inst_data.get("imds_v2_required", True)
                profile_arn = inst_data.get("instance_profile_arn")
                instance_id = inst_data.get(
                    "instance_id", inst_arn.split("/")[-1],
                )
                public_ip = inst_data.get("public_ip")
                state = inst_data.get("state", "unknown")

                if imds_v2_required or not profile_arn:
                    continue
                if state not in ("running", "unknown"):
                    continue

                detection = self._scorer.score("ec2:DescribeInstances")

                prob = 0.70
                notes_parts = [
                    f"IMDS Credential Theft — instance {instance_id} "
                    f"has IMDSv1 enabled with instance profile "
                    f"{profile_arn}.",
                    "An attacker with network access to the instance "
                    "can query http://169.254.169.254/ to steal "
                    "temporary role credentials without any API calls.",
                ]

                if public_ip:
                    prob = 0.80
                    notes_parts.append(
                        f"Instance has public IP {public_ip} — "
                        f"SSRF-based exploitation is possible from "
                        f"the internet."
                    )

                has_ssm = self._identity_has_permission(
                    source, "ssm:StartSession",
                )
                if has_ssm:
                    prob = 0.90
                    notes_parts.append(
                        "Caller has ssm:StartSession — can directly "
                        "access IMDS via SSM session."
                    )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=inst_arn,
                    edge_type=EdgeType.CAN_STEAL_IMDS_CREDS,
                    required_permissions=["ec2:DescribeInstances"],
                    api_actions=["ec2:DescribeInstances"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=self._scorer.get_noise_level(
                        "ec2:DescribeInstances",
                    ),
                    guardrail_status="clear",
                    conditions={
                        "imds_v2_required": False,
                        "instance_profile_arn": profile_arn,
                        "public_ip": public_ip,
                    },
                    notes=" ".join(notes_parts),
                ))

    # ==================================================================
    # ATTACK PATH 14: SSM Session / SendCommand
    # ==================================================================
    def _add_ssm_session_edges(self, ag: AttackGraph) -> None:
        """Add edges for SSM-based command execution on EC2 instances.

        If the caller has ``ssm:StartSession`` or ``ssm:SendCommand``,
        they can execute arbitrary commands on EC2 instances that have
        the SSM agent running.  This provides:
          - Shell access to the instance
          - Access to IMDS credentials (instance role)
          - Access to local files, environment variables, secrets
          - Lateral movement to other services the instance can reach

        Detection: SSM sessions generate CloudTrail events and are
        often monitored, but ``ssm:SendCommand`` with an inline script
        is harder to detect than interactive sessions.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        instances = self._env.nodes_of_type(NodeType.EC2_INSTANCE)

        for source in identities:
            has_start_session = self._identity_has_permission(
                source, "ssm:StartSession",
            )
            has_send_command = self._identity_has_permission(
                source, "ssm:SendCommand",
            )

            if not (has_start_session or has_send_command):
                continue

            for inst_arn in instances:
                inst_data = self._env.get_node_data(inst_arn)
                instance_id = inst_data.get(
                    "instance_id", inst_arn.split("/")[-1],
                )
                state = inst_data.get("state", "unknown")

                if state not in ("running", "unknown"):
                    continue

                if has_start_session:
                    api = "ssm:StartSession"
                    prob = 0.80
                    noise = NoiseLevel.MEDIUM
                else:
                    api = "ssm:SendCommand"
                    prob = 0.75
                    noise = NoiseLevel.HIGH

                detection = self._scorer.score(api)
                prob *= self._get_permission_confidence_multiplier(
                    source, api,
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=inst_arn,
                    edge_type=EdgeType.CAN_SSM_SESSION,
                    required_permissions=[api],
                    api_actions=[api],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=noise,
                    guardrail_status="clear",
                    notes=(
                        f"SSM {api.split(':')[1]} on instance "
                        f"{instance_id} — provides shell access, "
                        f"local credential access, and lateral "
                        f"movement capability."
                    ),
                ))

    # ==================================================================
    # ATTACK PATH 15: EC2 Volume Snapshot Looting
    # ==================================================================
    def _add_volume_snapshot_edges(self, ag: AttackGraph) -> None:
        """Add edges for creating snapshots of EC2 instance volumes.

        If the caller has ``ec2:CreateSnapshot`` (and optionally
        ``ec2:CreateVolume``), they can:
          1. Create a snapshot of any instance's EBS volume
          2. Create a new volume from the snapshot
          3. Attach it to an instance they control
          4. Mount and read the entire filesystem

        This extracts: credentials, SSH keys, source code, database
        files, configuration, application secrets — everything on disk.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        instances = self._env.nodes_of_type(NodeType.EC2_INSTANCE)

        for source in identities:
            has_create_snap = self._identity_has_permission(
                source, "ec2:CreateSnapshot",
            )
            if not has_create_snap:
                continue

            has_create_vol = self._identity_has_permission(
                source, "ec2:CreateVolume",
            )

            for inst_arn in instances:
                inst_data = self._env.get_node_data(inst_arn)
                instance_id = inst_data.get(
                    "instance_id", inst_arn.split("/")[-1],
                )

                detection = (
                    self._scorer.score("ec2:CreateSnapshot")
                    + self._scorer.score("ec2:CreateVolume")
                )
                prob = 0.85 if has_create_vol else 0.50
                prob *= self._get_permission_confidence_multiplier(
                    source, "ec2:CreateSnapshot",
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=inst_arn,
                    edge_type=EdgeType.CAN_SNAPSHOT_VOLUME,
                    required_permissions=["ec2:CreateSnapshot"],
                    api_actions=[
                        "ec2:CreateSnapshot",
                        "ec2:CreateVolume",
                        "ec2:AttachVolume",
                    ],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes=(
                        f"EC2 Volume Snapshot Loot — snapshot instance "
                        f"{instance_id} volumes, create a new volume, "
                        f"and mount it to extract credentials, SSH keys, "
                        f"source code, and secrets from the filesystem."
                    ),
                ))

    # ==================================================================
    # ATTACK PATH 16: EC2 UserData Injection
    # ==================================================================
    def _add_userdata_injection_edges(self, ag: AttackGraph) -> None:
        """Add edges for injecting malicious user data into EC2 instances.

        If the caller has ``ec2:ModifyInstanceAttribute``, they can
        replace an instance's user data script.  On next boot (or if
        the instance is stopped and started), the injected script runs
        as root/SYSTEM.

        This is a persistence + privilege escalation technique:
          - Inject a reverse shell or credential harvester
          - Runs with the instance's IAM role permissions
          - Survives instance restarts
          - Hard to detect (user data changes are rarely monitored)

        Requires the instance to be STOPPED to modify user data, so
        the attacker may also need ec2:StopInstances + ec2:StartInstances.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        instances = self._env.nodes_of_type(NodeType.EC2_INSTANCE)

        for source in identities:
            has_modify = self._identity_has_permission(
                source, "ec2:ModifyInstanceAttribute",
            )
            if not has_modify:
                continue

            has_stop = self._identity_has_permission(
                source, "ec2:StopInstances",
            )
            has_start = self._identity_has_permission(
                source, "ec2:StartInstances",
            )

            for inst_arn in instances:
                inst_data = self._env.get_node_data(inst_arn)
                instance_id = inst_data.get(
                    "instance_id", inst_arn.split("/")[-1],
                )
                state = inst_data.get("state", "unknown")

                detection = self._scorer.score(
                    "ec2:ModifyInstanceAttribute",
                )
                api_actions = ["ec2:ModifyInstanceAttribute"]

                if has_stop and has_start:
                    prob = 0.80
                    api_actions.extend([
                        "ec2:StopInstances", "ec2:StartInstances",
                    ])
                elif state == "stopped":
                    prob = 0.85
                else:
                    prob = 0.30

                prob *= self._get_permission_confidence_multiplier(
                    source, "ec2:ModifyInstanceAttribute",
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=inst_arn,
                    edge_type=EdgeType.CAN_MODIFY_USERDATA,
                    required_permissions=[
                        "ec2:ModifyInstanceAttribute",
                    ],
                    api_actions=api_actions,
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes=(
                        f"EC2 UserData Injection — modify instance "
                        f"{instance_id} user data to inject a "
                        f"malicious script that runs as root on next "
                        f"boot. Provides persistence and access to "
                        f"the instance role credentials."
                    ),
                ))


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
def _principal_matches(principal: Any, identity_arn: str) -> bool:
    """Check if a bucket policy principal matches an identity ARN."""
    if principal == "*":
        return True
    if isinstance(principal, str):
        if principal == "*":
            return True
        return principal == identity_arn or identity_arn.endswith(principal)

    if isinstance(principal, dict):
        aws_vals = principal.get("AWS", [])
        if isinstance(aws_vals, str):
            aws_vals = [aws_vals]
        for p in aws_vals:
            if p == "*":
                return True
            if p == identity_arn:
                return True
            # Match account root (arn:aws:iam::ACCOUNT:root)
            if ":root" in p:
                # If the root ARN's account matches the identity's account
                p_parts = p.split(":")
                i_parts = identity_arn.split(":")
                if len(p_parts) >= 5 and len(i_parts) >= 5:
                    if p_parts[4] == i_parts[4]:
                        return True
    return False
