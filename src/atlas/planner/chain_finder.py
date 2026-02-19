"""
atlas.planner.chain_finder
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers multi-hop attack chains through the attack graph.

A chain is an ordered sequence of edges: A → B → C.
Examples:
  - AssumeRole → then from that role, CreateAccessKey for another user
  - AssumeRole → then from that role, AssumeRole to a third role
  - ModifyTrust on RoleX → then AssumeRole to RoleX
  - AttachPolicy to self → then AssumeRole (which was previously blocked)

The ChainFinder uses the PathFinder's graph traversal but returns
structured AttackChain objects that the CLI can display and simulate.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from atlas.core.models import AttackChain, AttackEdge
from atlas.core.types import NoiseLevel
from atlas.planner.attack_graph import AttackGraph

logger = structlog.get_logger(__name__)

# Edge types that represent a credential pivot (you become a new identity)
_PIVOT_TYPES = {
    "can_assume",
    "can_create_key",
    "can_create_login_profile",  # set password for privileged user
    "can_update_login_profile",  # change password for privileged user
    "can_steal_imds_creds",  # IMDS theft gives you the role's credentials
    "can_ssm_session",       # SSM session gives shell + IMDS access to role
    "can_backdoor_ecs_task",  # ECS backdoor -> task role creds
    "can_enable_ssm_via_tags",  # CreateTags + StartSession -> EC2/role
    "can_ec2_instance_connect",  # EC2 Instance Connect — SSH access
    "can_ec2_serial_console_ssh",  # EC2 Serial Console — serial access
    "can_steal_lambda_creds",  # Lambda env vars /proc/self/environ
    "can_read_codebuild_env",  # CodeBuild env vars (CloudGoat codebuild_secrets)
    "can_read_beanstalk_env",  # Beanstalk option_settings — leaked creds (enterprise misconfig)
    "can_pivot_via_beanstalk_creds",  # env -> identity (creds may belong to this identity)
    "can_steal_ecs_task_creds",  # ECS container metadata 169.254.170.2
    "can_assume_via_oidc_misconfig",  # OIDC trust abuse -> become role
    "can_obtain_creds_via_cognito_identity_pool",  # identity pool -> temp creds
    "can_update_glue_dev_endpoint",  # SSH into Glue endpoint, steal role creds
}

# Edge types that represent escalation (you gain more power as yourself or via target)
_ESCALATION_TYPES = {
    "can_attach_policy", "can_put_policy", "can_modify_trust",
    "can_passrole", "can_update_lambda", "can_modify_userdata",
    "can_passrole_ec2", "can_passrole_ecs", "can_passrole_cloudformation",
    "can_passrole_glue", "can_passrole_autoscaling", "can_passrole_agentcore",
    "can_update_lambda_config",
    "can_backdoor_lambda",
    "can_modify_sagemaker_lifecycle", "can_create_eks_access_entry",
    "can_hijack_bedrock_agent",  # Update Lambda + InvokeAgent (CloudGoat bedrock_agent_hijacking)
    "can_add_user_to_group",
    "can_create_admin_user",
    "can_create_backdoor_role",
    "can_create_policy_version", "can_set_default_policy_version",
    "can_delete_or_detach_policy", "can_delete_permissions_boundary",
    "can_put_permissions_boundary",
    "can_create_eventbridge_rule",  # persistence: schedule/event-triggered automation
    "can_get_federation_token",  # persistence: survive access key deletion
    "can_create_codebuild_github_runner",  # persistence: CodeBuild + attacker repo
    "can_create_rogue_oidc_persistence",  # persistence: rogue OIDC IdP
    "can_create_roles_anywhere_persistence",  # persistence: IAM Roles Anywhere
}

# Edge types that are terminal (resource access, not identity pivot)
_TERMINAL_TYPES = {
    "can_read_s3", "can_write_s3",
    "can_get_ec2_password_data", "can_enumerate_ses",
    "can_share_ami", "can_share_ebs_snapshot", "can_share_rds_snapshot",
    "can_invoke_bedrock_model", "can_open_security_group_ingress",
    "can_modify_s3_acl_persistence",  # S3 ACL backdoor is terminal
    "can_snapshot_volume",  # volume loot is a terminal action
    "can_access_via_resource_policy",  # access via misconfigured policy
    "can_self_signup_cognito",  # create Cognito user (initial access)
    "can_takeover_cloudfront_origin",  # S3 bucket takeover (initial access)
    "can_access_efs_from_ec2",  # EC2 -> EFS mount and read (CloudGoat ecs_efs_attack)
}

# Defense evasion — degrade detection before/during operations
_EVASION_TYPES = {
    "can_modify_guardduty_detector",
    "can_modify_guardduty_ip_trust_list",
    "can_modify_guardduty_event_rules",
    "can_create_guardduty_suppression",
    "can_delete_guardduty_publishing_dest",
    "can_stop_cloudtrail",
    "can_delete_cloudtrail",
    "can_update_cloudtrail_config",
    "can_modify_cloudtrail_bucket_lifecycle",
    "can_modify_cloudtrail_event_selectors",
    "can_delete_dns_logs", "can_leave_organization",
    "can_remove_vpc_flow_logs",
}


class ChainFinder:
    """Discovers multi-hop attack chains from a source identity."""

    def __init__(
        self,
        attack_graph: AttackGraph,
        *,
        max_depth: int = 4,
        max_chains: int = 50,
    ) -> None:
        self._ag = attack_graph
        self._max_depth = max_depth
        self._max_chains = max_chains

    def find_chains(self, source: str) -> list[AttackChain]:
        """Find all attack chains from *source*, both single-hop and multi-hop.

        Returns chains sorted by total detection cost (quietest first).
        """
        chains: list[AttackChain] = []
        seen_signatures: set[str] = set()

        # Build an edge lookup: source_arn → list[AttackEdge]
        edge_map: dict[str, list[AttackEdge]] = {}
        for e in self._ag.edges:
            edge_map.setdefault(e.source_arn, []).append(e)

        # DFS from source
        self._dfs(
            source=source,
            current_path=[],
            edge_map=edge_map,
            chains=chains,
            seen_signatures=seen_signatures,
            visited=set(),
            depth=0,
        )

        # Sort by detection cost, then hop count
        chains.sort(key=lambda c: (c.total_detection_cost, c.hop_count))

        return chains[:self._max_chains]

    def _dfs(
        self,
        source: str,
        current_path: list[AttackEdge],
        edge_map: dict[str, list[AttackEdge]],
        chains: list[AttackChain],
        seen_signatures: set[str],
        visited: set[str],
        depth: int,
    ) -> None:
        """DFS to discover chains."""
        if depth > self._max_depth:
            return
        if len(chains) >= self._max_chains:
            return

        outgoing = edge_map.get(source, [])
        if not outgoing:
            return

        # Deduplicate outgoing by (edge_type, target) keeping lowest cost
        best: dict[tuple[str, str], AttackEdge] = {}
        for e in outgoing:
            key = (e.edge_type.value, e.target_arn)
            if key not in best or e.detection_cost < best[key].detection_cost:
                best[key] = e

        for edge in best.values():
            if edge.target_arn in visited:
                continue

            new_path = current_path + [edge]
            edge_type = edge.edge_type.value

            # Every path is a valid chain (including single-hop)
            sig = self._chain_signature(new_path)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                chains.append(self._build_chain(new_path))

            # Continue DFS only through pivot edges (assume role, create key)
            # Because after a pivot, you ARE the new identity and can act from it
            if edge_type in _PIVOT_TYPES and depth + 1 < self._max_depth:
                visited_copy = visited | {edge.target_arn}
                self._dfs(
                    source=edge.target_arn,
                    current_path=new_path,
                    edge_map=edge_map,
                    chains=chains,
                    seen_signatures=seen_signatures,
                    visited=visited_copy,
                    depth=depth + 1,
                )
            # Also continue from EC2 instance when reached via SSM (can follow to EFS)
            elif (
                edge_type in ("can_ssm_session", "can_enable_ssm_via_tags")
                and depth + 1 < self._max_depth
                and self._is_ec2_instance(edge.target_arn)
            ):
                visited_copy = visited | {edge.target_arn}
                self._dfs(
                    source=edge.target_arn,
                    current_path=new_path,
                    edge_map=edge_map,
                    chains=chains,
                    seen_signatures=seen_signatures,
                    visited=visited_copy,
                    depth=depth + 1,
                )

    @staticmethod
    def _is_ec2_instance(arn: str) -> bool:
        """True if ARN is an EC2 instance (not a role)."""
        return ":instance/" in arn and ":role/" not in arn

    @staticmethod
    def _chain_signature(edges: list[AttackEdge]) -> str:
        """Unique signature for a chain to avoid duplicates."""
        parts = []
        for e in edges:
            parts.append(f"{e.edge_type.value}:{e.source_arn}:{e.target_arn}")
        return "|".join(parts)

    @staticmethod
    def _build_chain(edges: list[AttackEdge]) -> AttackChain:
        """Build an AttackChain from a list of edges."""
        total_cost = sum(e.detection_cost for e in edges)
        total_prob = 1.0
        for e in edges:
            total_prob *= e.success_probability

        # Build objective description
        if len(edges) == 1:
            objective = edges[0].notes or edges[0].edge_type.value
        else:
            first = edges[0].source_arn.split("/")[-1]
            last_target = edges[-1].target_arn
            last_name = last_target.split("/")[-1] if "/" in last_target else last_target.split(":")[-1]
            last_type = edges[-1].edge_type.value
            objective = f"{len(edges)}-step chain: {first} → ... → {last_name} ({last_type})"

        return AttackChain(
            chain_id=uuid.uuid4().hex[:8],
            edges=list(edges),
            total_detection_cost=round(total_cost, 4),
            total_success_probability=round(total_prob, 4),
            hop_count=len(edges),
            objective=objective,
        )
