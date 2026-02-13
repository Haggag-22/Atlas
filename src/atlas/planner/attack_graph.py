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
    """

    def __init__(
        self,
        env_graph: EnvironmentGraph,
        scorer: DetectionScorer,
    ) -> None:
        self._env = env_graph
        self._scorer = scorer

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

        This is a persistence + credential harvesting vector.
        Detection cost is HIGH — key creation is monitored.
        """
        users = self._env.nodes_of_type(NodeType.USER)
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for source in identities:
            if self._identity_has_permission(source, "iam:CreateAccessKey"):
                for target_user in users:
                    if source == target_user:
                        continue  # self-key-creation is different
                    detection = self._scorer.score("iam:CreateAccessKey")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target_user,
                        edge_type=EdgeType.CAN_CREATE_KEY,
                        required_permissions=["iam:CreateAccessKey"],
                        api_actions=["iam:CreateAccessKey"],
                        detection_cost=detection,
                        success_probability=0.9,
                        noise_level=self._scorer.get_noise_level("iam:CreateAccessKey"),
                        guardrail_status="clear",
                        notes="Create access key for target user — credential harvesting.",
                    ))

    # ==================================================================
    # ATTACK PATH 3: Policy Attachment (iam:AttachUserPolicy / AttachRolePolicy)
    # ==================================================================
    def _add_policy_attachment_edges(self, ag: AttackGraph) -> None:
        """If identity A can attach policies, add edges to all targets.

        Classic privilege escalation: attach AdministratorAccess to yourself.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for source in identities:
            # Can attach to users
            if self._identity_has_permission(source, "iam:AttachUserPolicy"):
                for target in self._env.nodes_of_type(NodeType.USER):
                    detection = self._scorer.score("iam:AttachUserPolicy")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_ATTACH_POLICY,
                        required_permissions=["iam:AttachUserPolicy"],
                        api_actions=["iam:AttachUserPolicy"],
                        detection_cost=detection,
                        success_probability=0.9,
                        noise_level=self._scorer.get_noise_level("iam:AttachUserPolicy"),
                        guardrail_status="clear",
                        notes="Attach managed policy to user — direct privesc.",
                    ))

            # Can attach to roles
            if self._identity_has_permission(source, "iam:AttachRolePolicy"):
                for target in self._env.nodes_of_type(NodeType.ROLE):
                    detection = self._scorer.score("iam:AttachRolePolicy")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_ATTACH_POLICY,
                        required_permissions=["iam:AttachRolePolicy"],
                        api_actions=["iam:AttachRolePolicy"],
                        detection_cost=detection,
                        success_probability=0.85,
                        noise_level=self._scorer.get_noise_level("iam:AttachRolePolicy"),
                        guardrail_status="clear",
                        notes="Attach managed policy to role — escalation via role.",
                    ))

    # ==================================================================
    # ATTACK PATH 4: Inline Policy Creation (iam:PutUserPolicy / PutRolePolicy)
    # ==================================================================
    def _add_inline_policy_edges(self, ag: AttackGraph) -> None:
        """Inject arbitrary inline policies on users/roles."""
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        for source in identities:
            if self._identity_has_permission(source, "iam:PutUserPolicy"):
                for target in self._env.nodes_of_type(NodeType.USER):
                    detection = self._scorer.score("iam:PutUserPolicy")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_PUT_POLICY,
                        required_permissions=["iam:PutUserPolicy"],
                        api_actions=["iam:PutUserPolicy"],
                        detection_cost=detection,
                        success_probability=0.9,
                        noise_level=self._scorer.get_noise_level("iam:PutUserPolicy"),
                        guardrail_status="clear",
                        notes="Create inline policy on user — stealthier than managed policy (no ARN).",
                    ))

            if self._identity_has_permission(source, "iam:PutRolePolicy"):
                for target in self._env.nodes_of_type(NodeType.ROLE):
                    detection = self._scorer.score("iam:PutRolePolicy")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_PUT_POLICY,
                        required_permissions=["iam:PutRolePolicy"],
                        api_actions=["iam:PutRolePolicy"],
                        detection_cost=detection,
                        success_probability=0.85,
                        noise_level=self._scorer.get_noise_level("iam:PutRolePolicy"),
                        guardrail_status="clear",
                        notes="Create inline policy on role — privesc via role permissions.",
                    ))

    # ==================================================================
    # ATTACK PATH 5: PassRole Abuse (iam:PassRole + service create)
    # ==================================================================
    def _add_passrole_edges(self, ag: AttackGraph) -> None:
        """PassRole + Lambda/EC2 create = assume any role the service can use.

        This is a classic indirect privesc path.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        for source in identities:
            has_passrole = self._identity_has_permission(source, "iam:PassRole")
            has_create_lambda = self._identity_has_permission(source, "lambda:CreateFunction")
            has_update_lambda = self._identity_has_permission(source, "lambda:UpdateFunctionCode")

            if has_passrole and (has_create_lambda or has_update_lambda):
                for role in roles:
                    api = "lambda:CreateFunction" if has_create_lambda else "lambda:UpdateFunctionCode"
                    detection = (
                        self._scorer.score("iam:PassRole")
                        + self._scorer.score(api)
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role,
                        edge_type=EdgeType.CAN_PASSROLE,
                        required_permissions=["iam:PassRole", api],
                        api_actions=["iam:PassRole", api],
                        detection_cost=detection,
                        success_probability=0.75,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=f"PassRole + {api} — indirect privesc to target role via Lambda.",
                    ))

    # ==================================================================
    # ATTACK PATH 6: Trust Policy Modification (iam:UpdateAssumeRolePolicy)
    # ==================================================================
    def _add_trust_modification_edges(self, ag: AttackGraph) -> None:
        """Modify a role's trust policy to allow our identity to assume it.

        Very high detection cost but creates persistent backdoor access.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        for source in identities:
            if self._identity_has_permission(source, "iam:UpdateAssumeRolePolicy"):
                for target in roles:
                    detection = self._scorer.score("iam:UpdateAssumeRolePolicy")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_MODIFY_TRUST,
                        required_permissions=["iam:UpdateAssumeRolePolicy"],
                        api_actions=["iam:UpdateAssumeRolePolicy"],
                        detection_cost=detection,
                        success_probability=0.9,
                        noise_level=NoiseLevel.CRITICAL,
                        guardrail_status="clear",
                        notes="Modify trust policy — backdoor persistent role access. VERY HIGH NOISE.",
                    ))

    # ==================================================================
    # ATTACK PATH 7: Lambda Code Injection
    # ==================================================================
    def _add_lambda_privesc_edges(self, ag: AttackGraph) -> None:
        """Update Lambda function code to steal execution role credentials.

        The function's role becomes the attacker's new identity.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        lambdas = self._env.nodes_of_type(NodeType.LAMBDA_FUNCTION)

        for source in identities:
            if self._identity_has_permission(source, "lambda:UpdateFunctionCode"):
                for func_arn in lambdas:
                    func_data = self._env.get_node_data(func_arn)
                    role_arn = func_data.get("role_arn")
                    if not role_arn:
                        continue

                    detection = self._scorer.score("lambda:UpdateFunctionCode")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role_arn,
                        edge_type=EdgeType.CAN_UPDATE_LAMBDA,
                        required_permissions=["lambda:UpdateFunctionCode"],
                        api_actions=["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
                        detection_cost=detection,
                        success_probability=0.80,
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
                # --- Check IAM-based access ---
                has_read = any(
                    self._identity_has_permission(source, a) for a in s3_read_actions
                )
                has_write = any(
                    self._identity_has_permission(source, a) for a in s3_write_actions
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
    def _identity_has_permission(self, identity_arn: str, action: str) -> bool:
        """Check if an identity likely has a specific IAM permission.

        This performs a best-effort check by examining attached and inline
        policies in the environment graph.  It's not a perfect simulation
        (that would require iam:SimulatePrincipalPolicy), but it's good
        enough for attack graph construction.
        """
        # Check direct policy attachments
        outgoing = self._env.outgoing(identity_arn)
        for target_arn, edge_data in outgoing:
            edge_type = edge_data.get("edge_type", "")
            if edge_type in (EdgeType.HAS_POLICY.value, EdgeType.HAS_INLINE_POLICY.value):
                # Fast-path: recognize well-known admin policies by ARN
                if self._is_admin_policy_arn(target_arn):
                    return True
                policy_data = self._env.get_node_data(target_arn)
                doc = policy_data.get("policy_document", {})
                if self._policy_allows_action(doc, action):
                    return True

        # Check group memberships
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
        """Check if a policy document allows a specific action."""
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if a == "*" or a == action:
                    return True
                # Wildcard matching: iam:* matches iam:CreateAccessKey
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
