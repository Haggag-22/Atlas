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
            "can_passrole_ec2": "PassRole + EC2",
            "can_passrole_ecs": "PassRole + ECS",
            "can_passrole_cloudformation": "PassRole + CloudFormation",
            "can_passrole_glue": "PassRole + Glue",
            "can_passrole_autoscaling": "PassRole + AutoScaling",
            "can_modify_trust": "Trust Policy Modification",
            "can_update_lambda": "Lambda Code Injection",
            "can_update_lambda_config": "Lambda Config/Layer Update",
            "can_create_login_profile": "Create Login Profile",
            "can_update_login_profile": "Update Login Profile",
            "can_add_user_to_group": "Add User to Group",
            "can_create_policy_version": "Create Policy Version",
            "can_set_default_policy_version": "Set Default Policy Version",
            "can_delete_or_detach_policy": "Delete/Detach Policy",
            "can_delete_permissions_boundary": "Delete Permissions Boundary",
            "can_put_permissions_boundary": "Put Permissions Boundary",
            "can_update_glue_dev_endpoint": "Glue Dev Endpoint Update",
            "can_obtain_creds_via_cognito_identity_pool": "Cognito Identity Pool Creds",
            "can_create_eventbridge_rule": "EventBridge Rule Persistence",
            "can_get_federation_token": "GetFederationToken Persistence",
            "can_create_codebuild_github_runner": "CodeBuild GitHub Runner Persistence",
            "can_create_rogue_oidc_persistence": "Rogue OIDC IdP Persistence",
            "can_create_roles_anywhere_persistence": "IAM Roles Anywhere Persistence",
            "can_modify_s3_acl_persistence": "S3 ACL Persistence",
            "can_modify_guardduty_detector": "GuardDuty Detector Evasion",
            "can_modify_guardduty_ip_trust_list": "GuardDuty IP Trust List Evasion",
            "can_modify_guardduty_event_rules": "GuardDuty Event Rule Evasion",
            "can_create_guardduty_suppression": "GuardDuty Suppression Evasion",
            "can_delete_guardduty_publishing_dest": "GuardDuty Publishing Dest Evasion",
            "can_stop_cloudtrail": "CloudTrail Stop Logging Evasion",
            "can_delete_cloudtrail": "CloudTrail Delete Trail Evasion",
            "can_update_cloudtrail_config": "CloudTrail Config Update Evasion",
            "can_modify_cloudtrail_bucket_lifecycle": "CloudTrail Bucket Lifecycle Evasion",
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
            "can_steal_lambda_creds": "Lambda Credential Theft",
            "can_steal_ecs_task_creds": "ECS Task Role Compromise",
            "can_access_via_resource_policy": "Resource Policy Misconfiguration",
            "can_assume_via_oidc_misconfig": "OIDC Trust Policy Abuse",
            "can_self_signup_cognito": "Cognito Self-Signup",
            "can_takeover_cloudfront_origin": "CloudFront/S3 Domain Takeover",
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
        self._add_lambda_credential_theft_edges(ag)
        self._add_ecs_task_credential_theft_edges(ag)
        self._add_resource_policy_misconfig_edges(ag)
        self._add_oidc_trust_misconfig_edges(ag)
        self._add_cognito_self_signup_edges(ag)
        self._add_cloudfront_takeover_edges(ag)
        self._add_passrole_expanded_edges(ag)
        self._add_lambda_config_update_edges(ag)
        self._add_cognito_identity_pool_edges(ag)
        self._add_iam_privesc_edges(ag)
        self._add_eventbridge_persistence_edges(ag)
        self._add_post_exploitation_persistence_edges(ag)
        self._add_guardduty_evasion_edges(ag)
        self._add_cloudtrail_evasion_edges(ag)

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

            # Can attach to groups (if source is a user and member of that group)
            if source in self._env.nodes_of_type(NodeType.USER):
                for target in self._env.nodes_of_type(NodeType.GROUP):
                    if not self._identity_has_permission(
                        source, "iam:AttachGroupPolicy", resource_arn=target,
                    ):
                        continue
                    # Check if user is member of group (optional; broad check also valid)
                    detection = self._scorer.score("iam:AttachGroupPolicy")
                    prob = 0.85 * self._get_permission_confidence_multiplier(
                        source, "iam:AttachGroupPolicy", target,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_ATTACH_POLICY,
                        required_permissions=["iam:AttachGroupPolicy"],
                        api_actions=["iam:AttachGroupPolicy"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("iam:AttachGroupPolicy"),
                        guardrail_status="clear",
                        notes="Attach managed policy to group — escalation if member of group.",
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

            # Can put inline policy on group (if source is user and member of group)
            if source in self._env.nodes_of_type(NodeType.USER):
                for target in self._env.nodes_of_type(NodeType.GROUP):
                    if not self._identity_has_permission(
                        source, "iam:PutGroupPolicy", resource_arn=target,
                    ):
                        continue
                    detection = self._scorer.score("iam:PutGroupPolicy")
                    prob = 0.85 * self._get_permission_confidence_multiplier(
                        source, "iam:PutGroupPolicy", target,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_PUT_POLICY,
                        required_permissions=["iam:PutGroupPolicy"],
                        api_actions=["iam:PutGroupPolicy"],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=self._scorer.get_noise_level("iam:PutGroupPolicy"),
                        guardrail_status="clear",
                        notes="Create inline policy on group — privesc if member of group.",
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
                    notes=(
                        f"PassRole + {api} — indirect privesc to target "
                        f"role via Lambda. Lambda persistence: wire "
                        f"EventBridge schedule/event trigger for "
                        f"recurring execution."
                    ),
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
                    notes=(
                        "Modify trust policy — backdoor persistent role "
                        "access (IAM federation backdoor: add Federated "
                        "principal for attacker-controlled IdP). Survives "
                        "credential rotation. VERY HIGH NOISE."
                    ),
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
                    notes=(
                        "Lambda code injection — replace function code to "
                        "steal execution role creds. Lambda persistence: "
                        "modified code runs on every trigger; wire "
                        "EventBridge schedule for recurring execution."
                    ),
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
    # Initial Access technique — Hacking the Cloud:
    #   https://hackingthe.cloud/aws/general-knowledge/intro_metadata_service/
    #   https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
    # ==================================================================
    def _add_imds_credential_theft_edges(self, ag: AttackGraph) -> None:
        """Add edges for IMDS-based credential theft from EC2 instances.

        **Initial Access** technique.  EC2 instances with **IMDSv1 enabled**
        and an **instance profile** (IAM role) expose temporary credentials
        at ``http://169.254.169.254/latest/meta-data/iam/security-credentials/``
        via simple HTTP GET requests — no session token required.

        Exploitation vectors:
          - **SSRF**: Vulnerable web app (e.g. on public IP) coerced to
            request 169.254.169.254 → attacker obtains creds without
            code execution.  IMDSv2 mitigates this (requires PUT token).
          - **Code execution**: Shell/SSM access → direct curl to IMDS.
          - **XXE**: Similar to SSRF, application fetches external entity.

        The retrieved credentials are legitimate, AWS-issued, and often
        over-privileged.  Activity may appear normal in logs.  This has
        been a common entry point in real-world cloud breaches.

        The edge targets the **instance profile's role** (not the instance)
        so it chains into the identity graph.  Synthetic role nodes are
        created when needed.
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

                # Resolve instance profile → role ARN
                role_arn = self._resolve_instance_profile_role(
                    profile_arn, inst_arn,
                )

                detection = self._scorer.score("ec2:DescribeInstances")

                prob = 0.70
                attack_vector = "network_access"
                notes_parts = [
                    f"IMDS Credential Theft — instance {instance_id} "
                    f"has IMDSv1 enabled with instance profile "
                    f"{profile_arn}.",
                    "IMDSv1 allows simple GET requests to "
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                    "with no session token. Credentials are legitimate and "
                    "often over-privileged.",
                ]

                if public_ip:
                    prob = 0.80
                    attack_vector = "ssrf"
                    notes_parts.append(
                        f"Instance has public IP {public_ip} — "
                        "SSRF/XXE in a vulnerable web app can coerce a "
                        "server-side request to 169.254.169.254 to steal "
                        "creds without code execution (Initial Access from "
                        "internet)."
                    )

                notes_parts.append(
                    "Evasion: Use stolen creds from EC2 in same account "
                    "(no InstanceCredentialExfiltration.InsideAWS) or via "
                    "VPC Endpoints (SneakyEndpoints); GuardDuty detects "
                    "VPC bypass for 26+ services as of mid-2025."
                )

                has_ssm = self._identity_has_permission(
                    source, "ssm:StartSession",
                )
                if has_ssm:
                    prob = 0.90
                    attack_vector = "code_execution"
                    notes_parts.append(
                        "Caller has ssm:StartSession — can directly "
                        "access IMDS via SSM session (shell → curl)."
                    )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role_arn,
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
                        "instance_arn": inst_arn,
                        "public_ip": public_ip,
                        "attack_vector": attack_vector,
                    },
                    notes=" ".join(notes_parts),
                ))

    # ------------------------------------------------------------------
    # Helper: resolve instance profile ARN → role ARN
    # ------------------------------------------------------------------
    def _resolve_instance_profile_role(
        self, profile_arn: str, inst_arn: str,
    ) -> str:
        """Resolve an instance profile ARN to a role ARN.

        Strategy:
          1. Look for a ROLE node in the graph whose data has a matching
             instance profile (populated by the identity collector).
          2. Derive the role name from the instance profile name
             (AWS convention: profile name often matches role name).
          3. Ensure the role node exists in the graph (create a
             synthetic one if needed) so the attack graph can chain.
        """
        # Try to find a role whose instance profile matches
        for role_arn in self._env.nodes_of_type(NodeType.ROLE):
            role_data = self._env.get_node_data(role_arn)
            if role_data.get("instance_profile_arn") == profile_arn:
                return role_arn

        # Derive role ARN from instance profile ARN
        # arn:aws:iam::ACCOUNT:instance-profile/NAME → arn:aws:iam::ACCOUNT:role/NAME
        parts = profile_arn.split(":")
        if len(parts) >= 6 and "instance-profile/" in parts[5]:
            profile_name = parts[5].replace("instance-profile/", "")
            account_id = parts[4]
            role_arn = f"arn:aws:iam::{account_id}:role/{profile_name}"

            # Ensure the role node exists for path-finding
            if not self._env.has_node(role_arn):
                self._env.add_node(
                    role_arn, NodeType.ROLE,
                    data={
                        "arn": role_arn,
                        "role_name": profile_name,
                        "account_id": account_id,
                        "discovered_via": "instance_profile",
                        "instance_profile_arn": profile_arn,
                        "source_instance": inst_arn,
                    },
                    label=f"{profile_name} (via IMDS)",
                )
            return role_arn

        # Fallback: target the instance itself
        return inst_arn

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

        When the instance has an instance profile, the edge targets the
        profile's **role** (not the instance) to chain into the identity
        graph for path-finding.  Otherwise it targets the instance.
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
                profile_arn = inst_data.get("instance_profile_arn")

                if state not in ("running", "unknown"):
                    continue

                # Target the role if instance has a profile, else the instance
                if profile_arn:
                    target = self._resolve_instance_profile_role(
                        profile_arn, inst_arn,
                    )
                else:
                    target = inst_arn

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
                    target_arn=target,
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
                        f"movement capability. Connection tracking: "
                        f"established sessions persist through Security "
                        f"Group changes (defender isolation may not "
                        f"terminate existing shells)."
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
                        f"the instance role credentials. Connection "
                        f"tracking: established shells persist through "
                        f"Security Group swaps during incident response."
                    ),
                ))

    # ==================================================================
    # ATTACK PATH 17: Lambda Credential Theft (SSRF/XXE → /proc/self/environ)
    # Initial Access — https://hackingthe.cloud/aws/exploitation/lambda-steal-iam-credentials/
    # ==================================================================
    def _add_lambda_credential_theft_edges(self, ag: AttackGraph) -> None:
        """Add edges for stealing IAM credentials from Lambda functions.

        **Initial Access** technique.  Lambda execution role credentials
        are injected as environment variables (AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).  In Linux, these can be
        read from ``/proc/self/environ``.  If an attacker can trigger
        file read (XXE, SSRF with file://, deserialization) or coerce the
        function to read local files, they extract the role's credentials.

        Event data is also available via the Runtime API at
        ``http://169.254.100.1:9001/2018-06-01/runtime/invocation/next``
        (reachable via SSRF).  Unlike EC2 IMDS theft, **no GuardDuty
        alert** is generated for stolen Lambda credentials.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        lambdas = self._env.nodes_of_type(NodeType.LAMBDA_FUNCTION)

        for source in identities:
            if not self._identity_has_permission(
                source, "lambda:GetFunction",
            ) and not self._identity_has_permission(
                source, "lambda:ListFunctions",
            ):
                continue

            for func_arn in lambdas:
                func_data = self._env.get_node_data(func_arn)
                role_arn = func_data.get("role_arn")
                func_name = func_data.get("function_name", func_arn.split(":")[-1])

                if not role_arn:
                    continue

                # Ensure role node exists
                if not self._env.has_node(role_arn):
                    parts = role_arn.split(":")
                    role_name = parts[-1].split("/")[-1] if len(parts) >= 6 else "unknown"
                    account_id = parts[4] if len(parts) >= 5 else ""
                    self._env.add_node(
                        role_arn, NodeType.ROLE,
                        data={
                            "arn": role_arn,
                            "role_name": role_name,
                            "account_id": account_id,
                            "discovered_via": "lambda_execution_role",
                            "source_function": func_arn,
                        },
                        label=f"{role_name} (via Lambda)",
                    )

                detection = self._scorer.score("lambda:GetFunction")
                prob = 0.75
                notes = (
                    f"Lambda Credential Theft — function {func_name} has "
                    f"execution role {role_arn}. Credentials are in env vars "
                    f"(read /proc/self/environ via XXE/SSRF). Event data at "
                    f"169.254.100.1:9001. No GuardDuty alert for Lambda cred theft."
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role_arn,
                    edge_type=EdgeType.CAN_STEAL_LAMBDA_CREDS,
                    required_permissions=["lambda:GetFunction"],
                    api_actions=["lambda:GetFunction", "lambda:InvokeFunction"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=self._scorer.get_noise_level("lambda:GetFunction"),
                    guardrail_status="clear",
                    conditions={
                        "function_arn": func_arn,
                        "function_name": func_name,
                        "credential_source": "/proc/self/environ",
                    },
                    notes=notes,
                ))

    # ==================================================================
    # ATTACK PATH 18: ECS Task Role Compromise
    # Initial Access — metadata at 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
    # ==================================================================
    def _add_ecs_task_credential_theft_edges(self, ag: AttackGraph) -> None:
        """Add edges for stealing task role credentials from ECS containers.

        **Initial Access** technique.  ECS tasks with task roles receive
        credentials via the container metadata endpoint
        ``169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI``.  If an
        attacker gains RCE in the container (SSRF, command injection,
        deserialization, exposed debug endpoint), they can curl this
        endpoint and obtain the task role's temporary credentials.

        Task roles are often over-privileged (s3:*, iam:PassRole,
        sts:AssumeRole).  No GuardDuty alert for task role cred theft.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        task_defs = self._env.nodes_of_type(NodeType.ECS_TASK_DEFINITION)

        for source in identities:
            if not self._identity_has_permission(
                source, "ecs:DescribeTaskDefinition",
            ) and not self._identity_has_permission(
                source, "ecs:ListTaskDefinitions",
            ):
                continue

            for td_arn in task_defs:
                td_data = self._env.get_node_data(td_arn)
                role_arn = td_data.get("task_role_arn")
                family = td_data.get("family", td_arn.split("/")[-1])

                if not role_arn:
                    continue

                if not self._env.has_node(role_arn):
                    parts = role_arn.split(":")
                    role_name = parts[-1].split("/")[-1] if len(parts) >= 6 else "unknown"
                    account_id = parts[4] if len(parts) >= 5 else ""
                    self._env.add_node(
                        role_arn, NodeType.ROLE,
                        data={
                            "arn": role_arn,
                            "role_name": role_name,
                            "account_id": account_id,
                            "discovered_via": "ecs_task_role",
                            "source_task_definition": td_arn,
                        },
                        label=f"{role_name} (via ECS)",
                    )

                detection = self._scorer.score("ecs:DescribeTaskDefinition")
                prob = 0.70
                notes = (
                    f"ECS Task Role Compromise — task definition {family} "
                    f"has task role {role_arn}. Credentials at "
                    f"169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI. "
                    f"RCE (SSRF, cmd injection) in container → steal creds."
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role_arn,
                    edge_type=EdgeType.CAN_STEAL_ECS_TASK_CREDS,
                    required_permissions=["ecs:DescribeTaskDefinition"],
                    api_actions=["ecs:DescribeTaskDefinition", "ecs:DescribeTasks"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=self._scorer.get_noise_level("ecs:DescribeTaskDefinition"),
                    guardrail_status="clear",
                    conditions={
                        "task_definition_arn": td_arn,
                        "family": family,
                        "metadata_endpoint": "169.254.170.2",
                    },
                    notes=notes,
                ))

    # ==================================================================
    # ATTACK PATH 19: Misconfigured Resource-Based Policies
    # https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/
    # ==================================================================
    def _add_resource_policy_misconfig_edges(self, ag: AttackGraph) -> None:
        """Add edges for resources with dangerous resource policies.

        Resource policies with Principal \"*\", NotPrincipal, NotAction,
        or NotResource can grant unintended access.  Principal \"*\"
        means anyone with AWS credentials can act on the resource.
        NotPrincipal with Allow = everyone except X gets access.
        Resource-based Allow can succeed even without identity policy
        (same-account quirk).  Write access (PutObject, etc.) enables
        supply chain attacks (overwrite SDK, Lambda layer, container image).
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )

        # S3 buckets with resource policies
        for bucket_arn in self._env.nodes_of_type(NodeType.S3_BUCKET):
            bucket_data = self._env.get_node_data(bucket_arn)
            policy = bucket_data.get("bucket_policy")
            if not policy:
                continue

            misconfig = self._check_resource_policy_dangerous(policy)
            if not misconfig:
                continue

            for source in identities:
                detection = self._scorer.score("s3:GetObject")
                prob = 0.90 if "Principal" in misconfig and "*" in str(misconfig.get("Principal")) else 0.70
                notes = (
                    f"S3 bucket has misconfigured policy: {misconfig.get('reason', 'dangerous principal')}. "
                    f"Principal '*' or NotPrincipal can grant access without identity policy."
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=bucket_arn,
                    edge_type=EdgeType.CAN_ACCESS_VIA_RESOURCE_POLICY,
                    required_permissions=[],
                    api_actions=["s3:GetObject", "s3:PutObject"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.LOW,
                    guardrail_status="clear",
                    conditions={"policy_misconfig": misconfig},
                    notes=notes,
                ))

        # Lambda functions with resource policies
        for func_arn in self._env.nodes_of_type(NodeType.LAMBDA_FUNCTION):
            func_data = self._env.get_node_data(func_arn)
            policy = func_data.get("resource_policy")
            if not policy:
                continue

            misconfig = self._check_resource_policy_dangerous(policy)
            if not misconfig:
                continue

            for source in identities:
                detection = self._scorer.score("lambda:InvokeFunction")
                prob = 0.85
                notes = (
                    f"Lambda has misconfigured resource policy: {misconfig.get('reason', 'dangerous')}. "
                    f"Anyone may invoke; combine with Lambda credential theft for full compromise."
                )

                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=func_arn,
                    edge_type=EdgeType.CAN_ACCESS_VIA_RESOURCE_POLICY,
                    required_permissions=[],
                    api_actions=["lambda:InvokeFunction"],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.LOW,
                    guardrail_status="clear",
                    conditions={"policy_misconfig": misconfig},
                    notes=notes,
                ))

        # ECR repositories with resource policies (Principal "*")
        # Attacker needs ecr:GetAuthorizationToken via identity policy; resource policy grants pull/push.
        for repo_arn in self._env.nodes_of_type(NodeType.ECR_REPOSITORY):
            repo_data = self._env.get_node_data(repo_arn)
            policy = repo_data.get("resource_policy")
            if not policy:
                continue

            misconfig = self._check_resource_policy_dangerous(policy)
            if not misconfig:
                continue

            # Check which ECR actions the policy allows
            actions = self._ecr_policy_actions(policy)
            pull_ok = "ecr:BatchGetImage" in actions or "ecr:*" in actions
            push_ok = "ecr:PutImage" in actions or "ecr:*" in actions

            for source in identities:
                if not self._identity_has_permission(source, "ecr:GetAuthorizationToken"):
                    continue

                if pull_ok:
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=repo_arn,
                        edge_type=EdgeType.CAN_ACCESS_VIA_RESOURCE_POLICY,
                        required_permissions=["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                        api_actions=["ecr:GetLoginPassword", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                        detection_cost=self._scorer.score("ecr:BatchGetImage"),
                        success_probability=0.90,
                        noise_level=NoiseLevel.LOW,
                        guardrail_status="clear",
                        conditions={"policy_misconfig": misconfig, "access": "pull"},
                        notes=f"ECR repo has Principal '*'; can pull images (source code, secrets). {misconfig.get('reason', '')}",
                    ))
                if push_ok:
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=repo_arn,
                        edge_type=EdgeType.CAN_ACCESS_VIA_RESOURCE_POLICY,
                        required_permissions=[
                            "ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload",
                            "ecr:UploadLayerPart", "ecr:BatchCheckLayerAvailability",
                            "ecr:CompleteLayerUpload", "ecr:PutImage",
                        ],
                        api_actions=["ecr:GetLoginPassword", "ecr:PutImage"],
                        detection_cost=self._scorer.score("ecr:PutImage"),
                        success_probability=0.90,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        conditions={"policy_misconfig": misconfig, "access": "push"},
                        notes=f"ECR repo has Principal '*'; can push malicious images (supply chain). {misconfig.get('reason', '')}",
                    ))

    def _ecr_policy_actions(self, policy: dict) -> set[str]:
        """Extract ECR actions from policy statements."""
        actions: set[str] = set()
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            act = stmt.get("Action", [])
            if isinstance(act, str):
                act = [act]
            for a in act:
                if a == "ecr:*":
                    return {"ecr:*"}
                if a.startswith("ecr:"):
                    actions.add(a)
        return actions

    def _check_resource_policy_dangerous(self, policy: dict) -> dict | None:
        """Check if a resource policy has dangerous elements. Returns misconfig dict or None."""
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            return None

        for stmt in statements:
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal")
            not_principal = stmt.get("NotPrincipal")
            not_action = stmt.get("NotAction")
            not_resource = stmt.get("NotResource")

            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                return {"reason": "Principal '*'", "element": "Principal", "statement": stmt}
            if not_principal:
                return {"reason": "NotPrincipal with Allow", "element": "NotPrincipal", "statement": stmt}
            if not_action and principal in ("*", {"AWS": "*"}):
                return {"reason": "NotAction with Principal '*'", "element": "NotAction", "statement": stmt}
            if not_resource:
                return {"reason": "NotResource (typo risk)", "element": "NotResource", "statement": stmt}

        return None

    # ==================================================================
    # ATTACK PATH 20: OIDC Trust Policy Misconfig (GitLab, Terraform, GitHub, Cognito)
    # https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/
    # ==================================================================
    def _add_oidc_trust_misconfig_edges(self, ag: AttackGraph) -> None:
        """Add edges for roles with over-permissive OIDC trust policies.

        GitLab/Terraform/GitHub/Cognito OIDC roles that lack sub/aud
        restrictions can be assumed by anyone with a valid token from
        that IdP. External attacker -> role (initial access).
        """
        EXTERNAL = "external::oidc-abuser"

        for role_arn in self._env.nodes_of_type(NodeType.ROLE):
            role_data = self._env.get_node_data(role_arn)
            trust = role_data.get("trust_policy") or {}
            stmts = trust.get("Statement", [])
            if not isinstance(stmts, list):
                continue

            for stmt in stmts:
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                if not isinstance(principal, dict):
                    continue
                fed = principal.get("Federated", "")
                if not fed:
                    continue

                cond = stmt.get("Condition", {})
                oidc_type = ""
                notes = ""

                # Cognito Identity (Amplify CVE-2024-28056)
                if "cognito-identity.amazonaws.com" in fed:
                    if not self._cond_has_cognito_aud(cond):
                        oidc_type = "cognito"
                        notes = "Cognito trust without cognito-identity.amazonaws.com:aud; assumable via any identity pool (CVE-2024-28056)."

                # GitLab OIDC
                elif "oidc-provider/gitlab.com" in fed:
                    if "gitlab.com:sub" not in str(cond):
                        oidc_type = "gitlab"
                        notes = "GitLab OIDC trust without gitlab.com:sub; any GitLab project can assume."

                # Terraform Cloud OIDC
                elif "oidc-provider/app.terraform.io" in fed:
                    sub_val = self._get_cond_value(cond, "app.terraform.io:sub")
                    if not sub_val:
                        oidc_type = "terraform"
                        notes = "Terraform Cloud OIDC trust without app.terraform.io:sub."
                    elif "*" in str(sub_val):
                        oidc_type = "terraform"
                        notes = "Terraform Cloud OIDC trust has wildcard in sub; org prefix match allows takeover."

                # GitHub OIDC
                elif "oidc-provider/token.actions.githubusercontent.com" in fed:
                    if "token.actions.githubusercontent.com:sub" not in str(cond):
                        oidc_type = "github"
                        notes = "GitHub Actions OIDC trust without sub restriction; any repo can assume."

                if oidc_type:
                    ag.add_edge(AttackEdge(
                        source_arn=EXTERNAL,
                        target_arn=role_arn,
                        edge_type=EdgeType.CAN_ASSUME_VIA_OIDC_MISCONFIG,
                        required_permissions=[],
                        api_actions=["sts:AssumeRoleWithWebIdentity"],
                        detection_cost=self._scorer.score("sts:AssumeRoleWithWebIdentity"),
                        success_probability=0.85,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        conditions={"oidc_type": oidc_type},
                        notes=notes,
                    ))
                    break

    def _cond_has_cognito_aud(self, cond: dict) -> bool:
        """Check if condition has cognito-identity.amazonaws.com:aud."""
        for key, val in (cond or {}).items():
            if isinstance(val, dict) and "cognito-identity.amazonaws.com:aud" in val:
                return True
        return False

    def _get_cond_value(self, cond: dict, key: str) -> Any:
        """Get value for condition key (StringEquals, StringLike, etc.)."""
        for k, v in (cond or {}).items():
            if isinstance(v, dict) and key in v:
                return v[key]
        return None

    # ==================================================================
    # ATTACK PATH 21: Cognito Unintended Self-Signup
    # https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/
    # ==================================================================
    def _add_cognito_self_signup_edges(self, ag: AttackGraph) -> None:
        """Add edges when Cognito User Pool allows self-signup (no admin-only)."""
        EXTERNAL = "external::cognito-self-signup"

        for pool_arn in self._env.nodes_of_type(NodeType.COGNITO_USER_POOL):
            pool_data = self._env.get_node_data(pool_arn)
            admin_cfg = pool_data.get("admin_create_user_config", {})
            allow_admin_only = admin_cfg.get("AllowAdminCreateUserOnly", False)

            if allow_admin_only:
                continue

            ag.add_edge(AttackEdge(
                source_arn=EXTERNAL,
                target_arn=pool_arn,
                edge_type=EdgeType.CAN_SELF_SIGNUP_COGNITO,
                required_permissions=[],
                api_actions=["cognito-idp:SignUp"],
                detection_cost=self._scorer.score("cognito-idp:SignUp"),
                success_probability=0.90,
                noise_level=NoiseLevel.LOW,
                guardrail_status="clear",
                conditions={},
                notes="Cognito User Pool allows self-signup; attacker can create account via cognito-idp:SignUp (ClientId from app).",
            ))

    # ==================================================================
    # ATTACK PATH 22: CloudFront/S3 Domain Takeover
    # https://hackingthe.cloud/aws/exploitation/orphaned_cloudfront_or_dns_takeover_via_s3/
    # ==================================================================
    def _add_cloudfront_takeover_edges(self, ag: AttackGraph) -> None:
        """Add edges when CloudFront origin points to non-existent S3 bucket."""
        EXTERNAL = "external::cloudfront-takeover"
        known_buckets = {self._s3_bucket_name_from_arn(a) for a in self._env.nodes_of_type(NodeType.S3_BUCKET)}

        for dist_arn in self._env.nodes_of_type(NodeType.CLOUDFRONT_DISTRIBUTION):
            dist_data = self._env.get_node_data(dist_arn)
            origin_bucket = dist_data.get("origin_bucket", "")
            if not origin_bucket:
                continue
            if origin_bucket in known_buckets:
                continue

            ag.add_edge(AttackEdge(
                source_arn=EXTERNAL,
                target_arn=dist_arn,
                edge_type=EdgeType.CAN_TAKEOVER_CLOUDFRONT_ORIGIN,
                required_permissions=[],
                api_actions=["s3:CreateBucket"],
                detection_cost=0.5,
                success_probability=0.85,
                noise_level=NoiseLevel.LOW,
                guardrail_status="clear",
                conditions={"orphaned_bucket": origin_bucket},
                notes=f"CloudFront origin bucket '{origin_bucket}' not found; attacker can create bucket to serve malicious content.",
            ))

    # ==================================================================
    # ATTACK PATH 23: PassRole + EC2/ECS/CloudFormation/Glue/AutoScaling
    # https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
    # ==================================================================
    def _add_passrole_expanded_edges(self, ag: AttackGraph) -> None:
        """PassRole abuse with EC2, ECS, CloudFormation, Glue, AutoScaling.

        Each service can execute code/tasks with a passed role. Attacker
        creates resource with privileged role -> steals creds or runs
        privileged actions.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        # (service_action, edge_type, notes)
        passrole_chains: list[tuple[str, EdgeType, str]] = [
            ("ec2:RunInstances", EdgeType.CAN_PASSROLE_EC2,
             "PassRole + ec2:RunInstances — launch EC2 with instance profile, user-data exfiltrates creds."),
            ("ecs:RunTask", EdgeType.CAN_PASSROLE_ECS,
             "PassRole + ecs:RunTask — Fargate task with command override exfiltrates task role creds."),
            ("cloudformation:CreateStack", EdgeType.CAN_PASSROLE_CLOUDFORMATION,
             "PassRole + cloudformation:CreateStack — stack executes as passed role (full blast radius)."),
            ("glue:CreateDevEndpoint", EdgeType.CAN_PASSROLE_GLUE,
             "PassRole + glue:CreateDevEndpoint — SSH into endpoint, steal role creds from IMDS."),
            ("glue:CreateJob", EdgeType.CAN_PASSROLE_GLUE,
             "PassRole + glue:CreateJob — job runs with passed role; glue:StartJobRun triggers."),
            ("glue:UpdateJob", EdgeType.CAN_PASSROLE_GLUE,
             "PassRole + glue:UpdateJob — update job role/command, start job to steal creds."),
        ]

        for source in identities:
            for role in roles:
                if not self._identity_has_permission(
                    source, "iam:PassRole", resource_arn=role,
                ):
                    continue

                for action, edge_type, notes in passrole_chains:
                    if not self._identity_has_permission(source, action):
                        continue
                    detection = (
                        self._scorer.score("iam:PassRole")
                        + self._scorer.score(action)
                    )
                    prob = 0.75 * self._get_permission_confidence_multiplier(
                        source, "iam:PassRole", role,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role,
                        edge_type=edge_type,
                        required_permissions=["iam:PassRole", action],
                        api_actions=["iam:PassRole", action],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=notes,
                    ))

        # AutoScaling: needs CreateLaunchConfiguration or CreateLaunchTemplate
        # + CreateAutoScalingGroup or UpdateAutoScalingGroup
        for source in identities:
            for role in roles:
                if not self._identity_has_permission(
                    source, "iam:PassRole", resource_arn=role,
                ):
                    continue
                has_launch = (
                    self._identity_has_permission(
                        source, "autoscaling:CreateLaunchConfiguration",
                    )
                    or self._identity_has_permission(
                        source, "ec2:CreateLaunchTemplate",
                    )
                )
                has_asg = (
                    self._identity_has_permission(
                        source, "autoscaling:CreateAutoScalingGroup",
                    )
                    or self._identity_has_permission(
                        source, "autoscaling:UpdateAutoScalingGroup",
                    )
                )
                if not (has_launch and has_asg):
                    continue
                actions = ["iam:PassRole"]
                if self._identity_has_permission(
                    source, "autoscaling:CreateLaunchConfiguration",
                ):
                    actions.append("autoscaling:CreateLaunchConfiguration")
                if self._identity_has_permission(
                    source, "ec2:CreateLaunchTemplate",
                ):
                    actions.append("ec2:CreateLaunchTemplate")
                if self._identity_has_permission(
                    source, "autoscaling:CreateAutoScalingGroup",
                ):
                    actions.append("autoscaling:CreateAutoScalingGroup")
                if self._identity_has_permission(
                    source, "autoscaling:UpdateAutoScalingGroup",
                ):
                    actions.append("autoscaling:UpdateAutoScalingGroup")
                detection = sum(self._scorer.score(a) for a in actions)
                prob = 0.70 * self._get_permission_confidence_multiplier(
                    source, "iam:PassRole", role,
                )
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role,
                    edge_type=EdgeType.CAN_PASSROLE_AUTOSCALING,
                    required_permissions=["iam:PassRole"] + actions[1:],
                    api_actions=actions,
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="PassRole + AutoScaling — create launch config/template + ASG with privileged role.",
                ))

    # ==================================================================
    # ATTACK PATH 24: Lambda UpdateFunctionConfiguration
    # Role change or malicious Lambda layer injection
    # ==================================================================
    def _add_lambda_config_update_edges(self, ag: AttackGraph) -> None:
        """Update Lambda config: change execution role or add malicious layer."""
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        lambdas = self._env.nodes_of_type(NodeType.LAMBDA_FUNCTION)

        for source in identities:
            for func_arn in lambdas:
                if not self._identity_has_permission(
                    source, "lambda:UpdateFunctionConfiguration",
                    resource_arn=func_arn,
                ):
                    continue
                func_data = self._env.get_node_data(func_arn)
                role_arn = func_data.get("role_arn")
                if not role_arn:
                    continue

                detection = self._scorer.score("lambda:UpdateFunctionConfiguration")
                prob = 0.80 * self._get_permission_confidence_multiplier(
                    source, "lambda:UpdateFunctionConfiguration", func_arn,
                )
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role_arn,
                    edge_type=EdgeType.CAN_UPDATE_LAMBDA_CONFIG,
                    required_permissions=["lambda:UpdateFunctionConfiguration"],
                    api_actions=[
                        "lambda:UpdateFunctionConfiguration",
                        "lambda:InvokeFunction",
                    ],
                    detection_cost=detection,
                    success_probability=prob,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="UpdateFunctionConfiguration — add malicious Lambda layer or change execution role; code runs with role's permissions.",
                ))

    # ==================================================================
    # ATTACK PATH 25: Overpermissioned Cognito Identity Pools
    # https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/
    # ==================================================================
    def _add_cognito_identity_pool_edges(self, ag: AttackGraph) -> None:
        """Identity pool issues temp creds; if roles are overprivileged, escalation."""
        EXTERNAL = "external::cognito-identity-pool"

        for pool_arn in self._env.nodes_of_type(NodeType.COGNITO_IDENTITY_POOL):
            pool_data = self._env.get_node_data(pool_arn)
            roles = pool_data.get("roles", {}) or {}

            for role_key, role_arn in roles.items():
                if not role_arn:
                    continue
                # Edge: external (authenticated via user pool or unauthenticated)
                # -> obtains creds from identity pool -> role
                auth_type = "unauthenticated" if role_key == "unauthenticated" else "authenticated"
                ag.add_edge(AttackEdge(
                    source_arn=EXTERNAL,
                    target_arn=role_arn,
                    edge_type=EdgeType.CAN_OBTAIN_CREDS_VIA_COGNITO_IDENTITY_POOL,
                    required_permissions=[],
                    api_actions=[
                        "cognito-identity:GetId",
                        "cognito-identity:GetCredentialsForIdentity",
                    ],
                    detection_cost=(
                        self._scorer.score("cognito-identity:GetId")
                        + self._scorer.score(
                            "cognito-identity:GetCredentialsForIdentity"
                        )
                    ),
                    success_probability=0.85,
                    noise_level=NoiseLevel.MEDIUM,
                    guardrail_status="clear",
                    conditions={"auth_type": auth_type, "identity_pool": pool_arn},
                    notes=f"Cognito Identity Pool maps {auth_type} users to role; if role is overprivileged, attacker obtains temp creds with excessive permissions.",
                ))

    # ==================================================================
    # ATTACK PATH 26: IAM Privilege Escalation (LoginProfile, AddUserToGroup, etc.)
    # https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
    # ==================================================================
    def _add_iam_privesc_edges(self, ag: AttackGraph) -> None:
        """IAM direct privilege escalation: LoginProfile, AddUserToGroup, policy versions, etc."""
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        users = self._env.nodes_of_type(NodeType.USER)
        roles = self._env.nodes_of_type(NodeType.ROLE)
        groups = self._env.nodes_of_type(NodeType.GROUP)
        policies = self._env.nodes_of_type(NodeType.POLICY)

        # CreateLoginProfile -> target user (console access)
        for source in identities:
            for target in users:
                if source == target:
                    continue
                if not self._identity_has_permission(
                    source, "iam:CreateLoginProfile", resource_arn=target,
                ):
                    continue
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=target,
                    edge_type=EdgeType.CAN_CREATE_LOGIN_PROFILE,
                    required_permissions=["iam:CreateLoginProfile"],
                    api_actions=["iam:CreateLoginProfile"],
                    detection_cost=self._scorer.score("iam:CreateLoginProfile"),
                    success_probability=0.90,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="CreateLoginProfile — set console password for target user; gain their permissions.",
                ))

        # UpdateLoginProfile -> target user
        for source in identities:
            for target in users:
                if source == target:
                    continue
                if not self._identity_has_permission(
                    source, "iam:UpdateLoginProfile", resource_arn=target,
                ):
                    continue
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=target,
                    edge_type=EdgeType.CAN_UPDATE_LOGIN_PROFILE,
                    required_permissions=["iam:UpdateLoginProfile"],
                    api_actions=["iam:UpdateLoginProfile"],
                    detection_cost=self._scorer.score("iam:UpdateLoginProfile"),
                    success_probability=0.90,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="UpdateLoginProfile — change target user's console password; gain their permissions.",
                ))

        # AddUserToGroup -> add self to privileged group
        for source in identities:
            if source not in users:
                continue
            for group_arn in groups:
                if not self._identity_has_permission(
                    source, "iam:AddUserToGroup", resource_arn=group_arn,
                ):
                    continue
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=group_arn,
                    edge_type=EdgeType.CAN_ADD_USER_TO_GROUP,
                    required_permissions=["iam:AddUserToGroup"],
                    api_actions=["iam:AddUserToGroup"],
                    detection_cost=self._scorer.score("iam:AddUserToGroup"),
                    success_probability=0.90,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="AddUserToGroup — add self to group; inherit group's permissions.",
                ))

        # CreatePolicyVersion (policy that affects source)
        for source in identities:
            for policy_arn in policies:
                if not self._identity_has_permission(
                    source, "iam:CreatePolicyVersion", resource_arn=policy_arn,
                ):
                    continue
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=policy_arn,
                    edge_type=EdgeType.CAN_CREATE_POLICY_VERSION,
                    required_permissions=["iam:CreatePolicyVersion"],
                    api_actions=["iam:CreatePolicyVersion"],
                    detection_cost=self._scorer.score("iam:CreatePolicyVersion"),
                    success_probability=0.85,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="CreatePolicyVersion — create new version with --set-as-default; escalate if policy applies to self.",
                ))

        # SetDefaultPolicyVersion
        for source in identities:
            for policy_arn in policies:
                if not self._identity_has_permission(
                    source, "iam:SetDefaultPolicyVersion", resource_arn=policy_arn,
                ):
                    continue
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=policy_arn,
                    edge_type=EdgeType.CAN_SET_DEFAULT_POLICY_VERSION,
                    required_permissions=["iam:SetDefaultPolicyVersion"],
                    api_actions=["iam:SetDefaultPolicyVersion"],
                    detection_cost=self._scorer.score("iam:SetDefaultPolicyVersion"),
                    success_probability=0.80,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="SetDefaultPolicyVersion — revert to older version with more permissions.",
                ))

        # Delete/Detach policy (removes deny or boundary)
        for source in identities:
            for target in list(roles) + list(users):
                for perm in [
                    "iam:DeleteRolePolicy", "iam:DeleteUserPolicy",
                    "iam:DetachRolePolicy", "iam:DetachUserPolicy",
                ]:
                    if not self._identity_has_permission(
                        source, perm, resource_arn=target,
                    ):
                        continue
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_DELETE_OR_DETACH_POLICY,
                        required_permissions=[perm],
                        api_actions=[perm],
                        detection_cost=self._scorer.score(perm),
                        success_probability=0.75,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=f"{perm} — remove policy/boundary; may expand effective permissions.",
                    ))
                    break

        # DeletePermissionsBoundary
        for source in identities:
            for target in list(roles) + list(users):
                for perm in [
                    "iam:DeleteRolePermissionsBoundary",
                    "iam:DeleteUserPermissionsBoundary",
                ]:
                    if not self._identity_has_permission(
                        source, perm, resource_arn=target,
                    ):
                        continue
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_DELETE_PERMISSIONS_BOUNDARY,
                        required_permissions=[perm],
                        api_actions=[perm],
                        detection_cost=self._scorer.score(perm),
                        success_probability=0.80,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=f"{perm} — remove boundary; existing allows may expand.",
                    ))
                    break

        # PutPermissionsBoundary (weaken boundary)
        for source in identities:
            for target in list(roles) + list(users):
                for perm in [
                    "iam:PutRolePermissionsBoundary",
                    "iam:PutUserPermissionsBoundary",
                ]:
                    if not self._identity_has_permission(
                        source, perm, resource_arn=target,
                    ):
                        continue
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_PUT_PERMISSIONS_BOUNDARY,
                        required_permissions=[perm],
                        api_actions=[perm],
                        detection_cost=self._scorer.score(perm),
                        success_probability=0.75,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=f"{perm} — replace with weaker boundary; expand effective permissions.",
                    ))
                    break

        # glue:UpdateDevEndpoint (standalone — update SSH key, SSH in, steal creds)
        # Target: roles that trust glue.amazonaws.com (used by Glue dev endpoints)
        for source in identities:
            if not self._identity_has_permission(source, "glue:UpdateDevEndpoint"):
                continue
            # Target is any Glue endpoint we know about, or we add edge to a
            # synthetic "glue endpoint" if we don't collect them. For now,
            # add a generic edge when we have the permission (target = self,
            # meaning "can escalate via Glue"). Actually we need a target.
            # Glue dev endpoints have roles. We don't have GLUE_DEV_ENDPOINT.
            # Add edge: source -> role of any Glue endpoint. We don't collect
            # Glue endpoints. So we'll add a note that this is a potential
            # path when glue:UpdateDevEndpoint exists — we could add a synthetic
            # node "glue-dev-endpoint::*" or similar. Simpler: skip if no
            # endpoints, or add edge source -> source with a special meaning.
            # Better: add CAN_UPDATE_GLUE_DEV_ENDPOINT from source to a
            # placeholder "glue::escalation" or we iterate over roles that
            # trust glue.amazonaws.com. Let me add edges to roles that
            # trust glue.amazonaws.com.
            for role in roles:
                role_data = self._env.get_node_data(role)
                trust = role_data.get("trust_policy") or {}
                principals = self._extract_trust_principals(trust)
                if "glue.amazonaws.com" not in principals:
                    continue
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=role,
                    edge_type=EdgeType.CAN_UPDATE_GLUE_DEV_ENDPOINT,
                    required_permissions=["glue:UpdateDevEndpoint"],
                    api_actions=["glue:UpdateDevEndpoint"],
                    detection_cost=self._scorer.score("glue:UpdateDevEndpoint"),
                    success_probability=0.80,
                    noise_level=NoiseLevel.HIGH,
                    guardrail_status="clear",
                    notes="glue:UpdateDevEndpoint — update SSH key on existing endpoint, SSH in, steal role creds from IMDS.",
                ))

    def _extract_trust_principals(self, trust: dict) -> set[str]:
        """Extract service principals from trust policy."""
        principals: set[str] = set()
        for stmt in trust.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict):
                for svc in principal.get("Service", []) or []:
                    if isinstance(svc, str):
                        principals.add(svc)
            elif isinstance(principal, str) and principal == "*":
                principals.add("*")
        return principals

    # ==================================================================
    # ATTACK PATH 27: EventBridge Rule Persistence
    # Schedule/event-triggered automation; survives credential rotation
    # ==================================================================
    def _add_eventbridge_persistence_edges(self, ag: AttackGraph) -> None:
        """EventBridge rule persistence — create rules that trigger on schedule or events.

        If identity has events:PutRule, events:PutTargets, iam:PassRole,
        they can create a rule that targets Lambda (or other targets) with
        a privileged role. The rule runs on cron/rate or on events.
        Persistence: automation keeps executing without manual interaction;
        survives credential rotation when rule triggers Lambda with role.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)

        lambdas = self._env.nodes_of_type(NodeType.LAMBDA_FUNCTION)

        for source in identities:
            has_put_rule = self._identity_has_permission(source, "events:PutRule")
            has_put_targets = self._identity_has_permission(
                source, "events:PutTargets",
            )
            if not (has_put_rule and has_put_targets):
                continue

            # Path 1: Create new Lambda + EventBridge rule
            has_create_lambda = self._identity_has_permission(
                source, "lambda:CreateFunction",
            )
            if has_create_lambda:
                for role in roles:
                    if not self._identity_has_permission(
                        source, "iam:PassRole", resource_arn=role,
                    ):
                        continue
                    role_data = self._env.get_node_data(role)
                    trust = role_data.get("trust_policy") or {}
                    principals = self._extract_trust_principals(trust)
                    if "lambda.amazonaws.com" not in principals:
                        continue

                    detection = (
                        self._scorer.score("events:PutRule")
                        + self._scorer.score("events:PutTargets")
                        + self._scorer.score("lambda:CreateFunction")
                        + self._scorer.score("iam:PassRole")
                    )
                    prob = 0.80 * self._get_permission_confidence_multiplier(
                        source, "iam:PassRole", role,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role,
                        edge_type=EdgeType.CAN_CREATE_EVENTBRIDGE_RULE,
                        required_permissions=[
                            "events:PutRule",
                            "events:PutTargets",
                            "lambda:CreateFunction",
                            "iam:PassRole",
                        ],
                        api_actions=[
                            "lambda:CreateFunction",
                            "events:PutRule",
                            "events:PutTargets",
                            "events:EnableRule",
                        ],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        notes=(
                            "EventBridge rule persistence — create Lambda "
                            "with privileged role + rule with schedule "
                            "(cron/rate) or event trigger. Automation runs "
                            "independently; survives credential rotation."
                        ),
                    ))

            # Path 2: Target existing Lambda + EventBridge rule
            has_add_perm = self._identity_has_permission(
                source, "lambda:AddPermission",
            )
            if has_add_perm:
                for func_arn in lambdas:
                    if not self._identity_has_permission(
                        source, "lambda:AddPermission", resource_arn=func_arn,
                    ):
                        continue
                    func_data = self._env.get_node_data(func_arn)
                    role_arn = func_data.get("role_arn")
                    if not role_arn:
                        continue

                    detection = (
                        self._scorer.score("events:PutRule")
                        + self._scorer.score("events:PutTargets")
                        + self._scorer.score("lambda:AddPermission")
                    )
                    prob = 0.85 * self._get_permission_confidence_multiplier(
                        source, "lambda:AddPermission", func_arn,
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role_arn,
                        edge_type=EdgeType.CAN_CREATE_EVENTBRIDGE_RULE,
                        required_permissions=[
                            "events:PutRule",
                            "events:PutTargets",
                            "lambda:AddPermission",
                        ],
                        api_actions=[
                            "lambda:AddPermission",
                            "events:PutRule",
                            "events:PutTargets",
                            "events:EnableRule",
                        ],
                        detection_cost=detection,
                        success_probability=prob,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        notes=(
                            "EventBridge rule persistence — add rule "
                            "triggering existing Lambda on schedule or "
                            "events. Function runs with its role; "
                            "survives credential rotation."
                        ),
                    ))

    # ==================================================================
    # ATTACK PATH 27b: Post-Exploitation Persistence (Hacking The Cloud)
    # https://hackingthe.cloud/aws/post_exploitation/
    # ==================================================================
    def _add_post_exploitation_persistence_edges(self, ag: AttackGraph) -> None:
        """Add persistence edges from Hacking The Cloud post-exploitation techniques."""
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        roles = self._env.nodes_of_type(NodeType.ROLE)
        buckets = self._env.nodes_of_type(NodeType.S3_BUCKET)
        account_nodes = self._env.nodes_of_type(NodeType.ACCOUNT)
        root_targets = [
            a for a in account_nodes
            if a.endswith(":root") and ":root" in a and not a.endswith("aws:root")
        ]

        for source in identities:
            # 1. sts:GetFederationToken — survive access key deletion
            if self._identity_has_permission(source, "sts:GetFederationToken"):
                detection = self._scorer.score("sts:GetFederationToken")
                ag.add_edge(AttackEdge(
                    source_arn=source,
                    target_arn=source,
                    edge_type=EdgeType.CAN_GET_FEDERATION_TOKEN,
                    required_permissions=["sts:GetFederationToken"],
                    api_actions=["sts:GetFederationToken"],
                    detection_cost=detection,
                    success_probability=0.95,
                    noise_level=NoiseLevel.MEDIUM,
                    guardrail_status="clear",
                    notes=(
                        "Persistence — GetFederationToken returns temp creds "
                        "that survive access key deletion. Use before keys are "
                        "revoked. Console session from these creds bypasses "
                        "IAM/STS restrictions. https://hackingthe.cloud/aws/"
                        "post_exploitation/survive_access_key_deletion_with_sts_getfederationtoken/"
                    ),
                ))

            # 2. CodeBuild GitHub Runner — backdoor role + create project
            if (
                self._identity_has_permission(source, "iam:UpdateAssumeRolePolicy")
                and self._identity_has_permission(source, "codebuild:CreateProject")
            ):
                actions = [
                    "iam:UpdateAssumeRolePolicy",
                    "codebuild:CreateProject",
                    "codebuild:ImportSourceCredentials",
                ]
                has_import = self._identity_has_permission(
                    source, "codebuild:ImportSourceCredentials",
                )
                for role in roles:
                    if not self._identity_has_permission(
                        source, "iam:UpdateAssumeRolePolicy", resource_arn=role,
                    ):
                        continue
                    detection = sum(
                        self._scorer.score(a) for a in actions[:2]
                    ) + (self._scorer.score(actions[2]) if has_import else 0)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role,
                        edge_type=EdgeType.CAN_CREATE_CODEBUILD_GITHUB_RUNNER,
                        required_permissions=actions[:2],
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.75,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "CodeBuild GitHub Runner persistence — add "
                            "codebuild.amazonaws.com to role trust, create "
                            "Runner project linked to attacker GitHub repo. "
                            "Workflows execute in account with role creds. "
                            "https://hackingthe.cloud/aws/post_exploitation/"
                            "codebuild_github_runner_persistence/"
                        ),
                    ))

            # 3. IAM Rogue OIDC Identity Provider
            if (
                self._identity_has_permission(source, "iam:CreateOpenIDConnectProvider")
                and self._identity_has_permission(source, "iam:UpdateAssumeRolePolicy")
            ):
                for role in roles:
                    if not self._identity_has_permission(
                        source, "iam:UpdateAssumeRolePolicy", resource_arn=role,
                    ):
                        continue
                    actions = [
                        "iam:CreateOpenIDConnectProvider",
                        "iam:UpdateAssumeRolePolicy",
                    ]
                    detection = sum(self._scorer.score(a) for a in actions)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=role,
                        edge_type=EdgeType.CAN_CREATE_ROGUE_OIDC_PERSISTENCE,
                        required_permissions=actions,
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.70,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "Rogue OIDC IdP persistence — deploy attacker "
                            "OIDC server, create IdP in account, backdoor "
                            "role trust. Assume via AssumeRoleWithWebIdentity. "
                            "https://hackingthe.cloud/aws/post_exploitation/"
                            "iam_rogue_oidc_identity_provider/"
                        ),
                    ))

            # 4. IAM Roles Anywhere — trust anchor + profile
            if (
                self._identity_has_permission(source, "rolesanywhere:CreateTrustAnchor")
                and self._identity_has_permission(source, "rolesanywhere:CreateProfile")
                and self._identity_has_permission(source, "iam:CreateRole")
                and root_targets
            ):
                actions = [
                    "rolesanywhere:CreateTrustAnchor",
                    "rolesanywhere:CreateProfile",
                    "iam:CreateRole",
                ]
                detection = sum(self._scorer.score(a) for a in actions)
                for target in root_targets:
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_CREATE_ROLES_ANYWHERE_PERSISTENCE,
                        required_permissions=actions,
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.80,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "IAM Roles Anywhere persistence — register "
                            "attacker CA as trust anchor, create profile, "
                            "role. Obtain temp creds from outside AWS via "
                            "signed cert. https://hackingthe.cloud/aws/"
                            "post_exploitation/iam_roles_anywhere_persistence/"
                        ),
                    ))

            # 5. S3 File ACL persistence
            s3_acl_actions = [
                "s3:PutBucketAcl",
                "s3:PutObjectAcl",
                "s3:PutObjectVersionAcl",
            ]
            has_acl = any(
                self._identity_has_permission(source, a) for a in s3_acl_actions
            )
            if has_acl:
                for bucket_arn in buckets:
                    bucket_acl_ok = self._identity_has_permission(
                        source, "s3:PutBucketAcl", resource_arn=bucket_arn,
                    )
                    object_acl_ok = self._identity_has_permission(
                        source, "s3:PutObjectAcl", resource_arn=bucket_arn,
                    ) or self._identity_has_permission(
                        source, "s3:PutObjectVersionAcl", resource_arn=bucket_arn,
                    )
                    if not (bucket_acl_ok or object_acl_ok):
                        continue
                    used = [a for a in s3_acl_actions if self._identity_has_permission(
                        source, a, resource_arn=bucket_arn,
                    )]
                    if not used:
                        continue
                    detection = sum(self._scorer.score(a) for a in used)
                    bucket_name = self._env.get_node_data(bucket_arn).get(
                        "name", bucket_arn.split(":::")[-1],
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=bucket_arn,
                        edge_type=EdgeType.CAN_MODIFY_S3_ACL_PERSISTENCE,
                        required_permissions=used,
                        api_actions=used,
                        detection_cost=detection,
                        success_probability=0.85,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        notes=(
                            f"S3 ACL persistence — grant attacker account "
                            f"read/write via ACL on bucket '{bucket_name}' "
                            f"or objects. Bypasses bucket policy alerts. "
                            f"https://hackingthe.cloud/aws/post_exploitation/"
                            f"s3_acl_persistence/"
                        ),
                    ))

    # ==================================================================
    # ATTACK PATH 28: GuardDuty Defense Evasion
    # https://hackingthe.cloud/aws/avoiding-detection/modify-guardduty-config/
    # ==================================================================
    def _add_guardduty_evasion_edges(self, ag: AttackGraph) -> None:
        """Defense evasion — modify GuardDuty to reduce detection.

        Stealth-focused: modifying (vs deleting) is less likely to raise
        alerts while degrading detection effectiveness. Delegated admin
        architecture limits scope to member accounts.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        account_nodes = self._env.nodes_of_type(NodeType.ACCOUNT)
        root_targets = [
            a for a in account_nodes
            if a.endswith(":root") and ":root" in a
            and not a.endswith("aws:root")
        ]
        if not root_targets:
            return

        for source in identities:
            for target in root_targets:
                if (
                    self._identity_has_permission(source, "guardduty:ListDetectors")
                    and self._identity_has_permission(source, "guardduty:UpdateDetector")
                ):
                    detection = (
                        self._scorer.score("guardduty:ListDetectors")
                        + self._scorer.score("guardduty:UpdateDetector")
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_MODIFY_GUARDDUTY_DETECTOR,
                        required_permissions=[
                            "guardduty:ListDetectors",
                            "guardduty:UpdateDetector",
                        ],
                        api_actions=[
                            "guardduty:ListDetectors",
                            "guardduty:UpdateDetector",
                        ],
                        detection_cost=detection,
                        success_probability=0.85,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "GuardDuty evasion — disable detector, remove "
                            "S3/K8s data sources, or set finding frequency "
                            "to 6h. Modifying (vs deleting) is stealthier."
                        ),
                    ))

                if (
                    self._identity_has_permission(source, "guardduty:ListDetectors")
                    and self._identity_has_permission(source, "guardduty:ListIPSets")
                    and (
                        self._identity_has_permission(source, "guardduty:CreateIPSet")
                        or self._identity_has_permission(source, "guardduty:UpdateIPSet")
                    )
                ):
                    actions = [
                        "guardduty:ListDetectors",
                        "guardduty:ListIPSets",
                        "guardduty:CreateIPSet",
                        "guardduty:UpdateIPSet",
                    ]
                    detection = sum(self._scorer.score(a) for a in actions)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_MODIFY_GUARDDUTY_IP_TRUST_LIST,
                        required_permissions=actions[:4],
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.80,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "GuardDuty evasion — add IP to trusted list; "
                            "CloudTrail/VPC flow alerts suppressed. DNS exempt."
                        ),
                    ))

                if (
                    self._identity_has_permission(source, "events:ListRules")
                    and self._identity_has_permission(source, "events:PutRule")
                    and self._identity_has_permission(source, "events:RemoveTargets")
                ):
                    actions = [
                        "events:ListRules",
                        "events:ListTargetsByRule",
                        "events:PutRule",
                        "events:RemoveTargets",
                    ]
                    detection = sum(self._scorer.score(a) for a in actions)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_MODIFY_GUARDDUTY_EVENT_RULES,
                        required_permissions=actions,
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.85,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "GuardDuty evasion — disable or modify "
                            "GuardDuty EventBridge rule; blocks "
                            "auto-remediation in member accounts."
                        ),
                    ))

                if self._identity_has_permission(source, "guardduty:CreateFilter"):
                    detection = self._scorer.score("guardduty:CreateFilter")
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_CREATE_GUARDDUTY_SUPPRESSION,
                        required_permissions=["guardduty:CreateFilter"],
                        api_actions=["guardduty:CreateFilter"],
                        detection_cost=detection,
                        success_probability=0.90,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        notes=(
                            "GuardDuty evasion — create filter with "
                            "ARCHIVE action; findings auto-archived."
                        ),
                    ))

                if self._identity_has_permission(
                    source, "guardduty:DeletePublishingDestination",
                ):
                    detection = self._scorer.score(
                        "guardduty:DeletePublishingDestination",
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_DELETE_GUARDDUTY_PUBLISHING_DEST,
                        required_permissions=[
                            "guardduty:DeletePublishingDestination",
                        ],
                        api_actions=["guardduty:DeletePublishingDestination"],
                        detection_cost=detection,
                        success_probability=0.95,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "GuardDuty evasion — delete publishing "
                            "destination; findings no longer delivered."
                        ),
                    ))

    # ==================================================================
    # ATTACK PATH 29: CloudTrail Defense Evasion
    # https://hackingthe.cloud/aws/avoiding-detection/cloudtrail-evasion/
    # ==================================================================
    def _add_cloudtrail_evasion_edges(self, ag: AttackGraph) -> None:
        """Defense evasion — disable or degrade CloudTrail logging.

        Category 1 (Disabling): Stop logging, delete trails, update config,
        S3 lifecycle/retention. Category 2 (Obscuring) is operational
        guidance (unused regions, short-lived actions, etc.) — not graph edges.
        """
        identities = (
            self._env.nodes_of_type(NodeType.USER)
            + self._env.nodes_of_type(NodeType.ROLE)
        )
        account_nodes = self._env.nodes_of_type(NodeType.ACCOUNT)
        root_targets = [
            a for a in account_nodes
            if a.endswith(":root") and ":root" in a
            and not a.endswith("aws:root")
        ]
        if not root_targets:
            return

        for source in identities:
            for target in root_targets:
                # Stop CloudTrail — pause logging; creates forensic gaps
                if (
                    self._identity_has_permission(source, "cloudtrail:DescribeTrails")
                    and self._identity_has_permission(source, "cloudtrail:StopLogging")
                ):
                    actions = ["cloudtrail:DescribeTrails", "cloudtrail:StopLogging"]
                    detection = sum(self._scorer.score(a) for a in actions)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_STOP_CLOUDTRAIL,
                        required_permissions=actions,
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.90,
                        noise_level=NoiseLevel.CRITICAL,
                        guardrail_status="clear",
                        notes=(
                            "CloudTrail evasion — stop logging; actions during "
                            "the gap leave little trace. Triggers GuardDuty "
                            "Stealth:IAMUser/CloudTrailLoggingDisabled (high)."
                        ),
                    ))

                # Delete trails — removes future event capture
                if (
                    self._identity_has_permission(source, "cloudtrail:DescribeTrails")
                    and self._identity_has_permission(source, "cloudtrail:DeleteTrail")
                ):
                    actions = ["cloudtrail:DescribeTrails", "cloudtrail:DeleteTrail"]
                    detection = sum(self._scorer.score(a) for a in actions)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_DELETE_CLOUDTRAIL,
                        required_permissions=actions,
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.90,
                        noise_level=NoiseLevel.CRITICAL,
                        guardrail_status="clear",
                        notes=(
                            "CloudTrail evasion — delete trail; eliminates "
                            "mechanism capturing future events. Triggers "
                            "Stealth:IAMUser/CloudTrailLoggingDisabled (high)."
                        ),
                    ))

                # Update trail config — reduce coverage (regions, data events, dest)
                if (
                    self._identity_has_permission(source, "cloudtrail:DescribeTrails")
                    and self._identity_has_permission(source, "cloudtrail:UpdateTrail")
                ):
                    actions = ["cloudtrail:DescribeTrails", "cloudtrail:UpdateTrail"]
                    detection = sum(self._scorer.score(a) for a in actions)
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_UPDATE_CLOUDTRAIL_CONFIG,
                        required_permissions=actions,
                        api_actions=actions,
                        detection_cost=detection,
                        success_probability=0.85,
                        noise_level=NoiseLevel.HIGH,
                        guardrail_status="clear",
                        notes=(
                            "CloudTrail evasion — update trail config: reduce "
                            "data events, change regions, alter destinations. "
                            "Stealthier than stop/delete; logging still appears enabled."
                        ),
                    ))

                # S3 lifecycle on CloudTrail log bucket — shorten retention
                if self._identity_has_permission(
                    source, "s3:PutBucketLifecycleConfiguration",
                ):
                    detection = self._scorer.score(
                        "s3:PutBucketLifecycleConfiguration",
                    )
                    ag.add_edge(AttackEdge(
                        source_arn=source,
                        target_arn=target,
                        edge_type=EdgeType.CAN_MODIFY_CLOUDTRAIL_BUCKET_LIFECYCLE,
                        required_permissions=[
                            "s3:PutBucketLifecycleConfiguration",
                        ],
                        api_actions=["s3:PutBucketLifecycleConfiguration"],
                        detection_cost=detection,
                        success_probability=0.80,
                        noise_level=NoiseLevel.MEDIUM,
                        guardrail_status="clear",
                        notes=(
                            "CloudTrail evasion — modify S3 lifecycle on any "
                            "bucket; CloudTrail log buckets are high-value "
                            "targets. Shorten retention so evidence expires sooner."
                        ),
                    ))

    def _s3_bucket_name_from_arn(self, arn: str) -> str:
        """Extract bucket name from S3 ARN."""
        if arn.startswith("arn:aws:s3:::"):
            return arn.replace("arn:aws:s3:::", "").split("/")[0]
        return ""


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
