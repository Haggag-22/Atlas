"""
atlas.planner.strategies.privesc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Privilege escalation strategy.

Finds paths from the current identity to a higher-privilege identity
(admin role, powerful user, etc.) using the attack graph.

Strategy selection hierarchy (quietest first):
  1. Living-off-the-land: assume existing roles via trust policies (lowest noise)
  2. Credential harvesting: create access keys for privileged users (medium noise)
  3. Policy injection: attach/put policies to escalate permissions (high noise)
  4. PassRole abuse: create Lambda with privileged role (high noise)
  5. Trust modification: backdoor a role's trust policy (critical noise)
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from atlas.core.models import AttackPlan, PlannedAction
from atlas.core.types import NoiseLevel, Strategy
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.noise_budget import NoiseBudgetManager
from atlas.planner.path_finder import AttackPath, PathFinder
from atlas.planner.strategies.base import BaseStrategy

logger = structlog.get_logger(__name__)


class PrivilegeEscalationStrategy(BaseStrategy):
    """Find the lowest-noise path to privilege escalation."""

    @property
    def strategy_id(self) -> str:
        return Strategy.SLOW_ESCALATION.value

    @property
    def description(self) -> str:
        return "Find lowest-noise privilege escalation paths."

    def evaluate(
        self,
        *,
        current_identity: str,
        target: str,
        attack_graph: AttackGraph,
        path_finder: PathFinder,
        noise_budget: NoiseBudgetManager,
        context: dict[str, Any],
    ) -> AttackPlan | None:
        """Evaluate all escalation paths and return the best plan."""

        # Find multiple path types
        candidates: list[AttackPath] = []

        # 1. Quietest path (primary preference)
        quietest = path_finder.quietest_path(current_identity, target)
        if quietest and quietest.is_viable:
            candidates.append(quietest)

        # 2. Most reliable path
        reliable = path_finder.most_reliable_path(current_identity, target)
        if reliable and reliable.is_viable:
            candidates.append(reliable)

        # 3. Shortest path
        shortest = path_finder.shortest_path(current_identity, target)
        if shortest and shortest.is_viable:
            candidates.append(shortest)

        # 4. All paths within budget
        all_paths = path_finder.all_paths(
            current_identity, target, max_depth=6, max_paths=10,
        )
        candidates.extend(all_paths)

        if not candidates:
            logger.info(
                "no_escalation_paths_found",
                source=current_identity,
                target=target,
            )
            return None

        # Deduplicate by node sequence
        seen: set[tuple[str, ...]] = set()
        unique: list[AttackPath] = []
        for path in candidates:
            key = tuple(path.nodes)
            if key not in seen:
                seen.add(key)
                unique.append(path)

        # Filter by noise budget
        affordable = [
            p for p in unique
            if noise_budget.can_afford(p.total_detection_cost)
        ]

        if not affordable:
            logger.warning(
                "all_paths_exceed_noise_budget",
                paths_found=len(unique),
                budget_remaining=noise_budget.remaining,
            )
            # Fall back to cheapest available path even if over budget
            affordable = sorted(unique, key=lambda p: p.total_detection_cost)[:1]

        # Select best path: lowest detection cost among affordable
        best = min(affordable, key=lambda p: p.total_detection_cost)

        # Convert path to plan
        plan = self._path_to_plan(best, current_identity, target, len(unique))

        logger.info(
            "escalation_plan_selected",
            path_type=best.path_type,
            hops=best.hop_count,
            detection_cost=best.total_detection_cost,
            success_probability=best.total_success_probability,
            alternatives=len(unique) - 1,
        )

        return plan

    # ------------------------------------------------------------------
    # Convert an AttackPath to an AttackPlan
    # ------------------------------------------------------------------
    def _path_to_plan(
        self,
        path: AttackPath,
        source: str,
        target: str,
        alternatives: int,
    ) -> AttackPlan:
        """Convert an AttackPath into a list of PlannedActions."""
        plan_id = uuid.uuid4().hex[:12]
        steps: list[PlannedAction] = []
        reasoning: list[str] = [
            f"Selected {path.path_type} path with {path.hop_count} hops.",
            f"Total detection cost: {path.total_detection_cost:.4f}",
            f"Success probability: {path.total_success_probability:.4f}",
            f"Considered {alternatives} alternative paths.",
        ]

        for i, edge_data in enumerate(path.edges):
            source_node = path.nodes[i]
            target_node = path.nodes[i + 1]
            edge_type = edge_data.get("edge_type", "unknown")

            action_type = self._edge_type_to_action(edge_type)
            api_actions = edge_data.get("api_actions", [])
            detection_cost = edge_data.get("detection_cost", 0.0)
            noise = edge_data.get("noise_level", "medium")

            # Calculate pace hint based on noise level
            pace = self._calculate_pace(noise, i, len(path.edges))

            step = PlannedAction(
                action_id=f"{plan_id}-step-{i:02d}",
                action_type=action_type,
                source_arn=source_node,
                target_arn=target_node,
                api_calls=api_actions,
                parameters=edge_data.get("conditions", {}),
                detection_cost=detection_cost,
                success_probability=edge_data.get("success_probability", 1.0),
                noise_level=NoiseLevel(noise) if noise in NoiseLevel.__members__.values() else NoiseLevel.MEDIUM,
                pace_hint_seconds=pace,
                stealth_notes=edge_data.get("notes", ""),
                rollback_type=self._get_rollback_type(edge_type),
                depends_on=[f"{plan_id}-step-{i-1:02d}"] if i > 0 else [],
            )
            steps.append(step)

            reasoning.append(
                f"Step {i}: {action_type} from {source_node.split('/')[-1]} "
                f"to {target_node.split('/')[-1]} "
                f"(detection: {detection_cost:.3f}, pace: {pace:.0f}s)"
            )

        return AttackPlan(
            plan_id=plan_id,
            strategy=self.strategy_id,
            objective=f"Escalate from {source.split('/')[-1]} to {target.split('/')[-1]}",
            steps=steps,
            total_detection_cost=path.total_detection_cost,
            estimated_success_probability=path.total_success_probability,
            reasoning=reasoning,
            alternative_paths=alternatives - 1,
        )

    @staticmethod
    def _edge_type_to_action(edge_type: str) -> str:
        """Map graph edge types to executor action types."""
        mapping = {
            "can_assume": "assume_role",
            "can_create_key": "create_access_key",
            "can_attach_policy": "attach_policy",
            "can_put_policy": "put_inline_policy",
            "can_passrole": "passrole_lambda",
            "can_passrole_ec2": "passrole_ec2",
            "can_passrole_ecs": "passrole_ecs",
            "can_passrole_cloudformation": "passrole_cloudformation",
            "can_passrole_glue": "passrole_glue",
            "can_passrole_autoscaling": "passrole_autoscaling",
            "can_passrole_agentcore": "passrole_agentcore",
            "can_modify_trust": "modify_trust_policy",
            "can_update_lambda": "update_lambda_code",
            "can_update_lambda_config": "update_lambda_config",
            "can_create_lambda": "create_lambda",
            "can_create_login_profile": "create_login_profile",
            "can_update_login_profile": "update_login_profile",
            "can_add_user_to_group": "add_user_to_group",
            "can_create_policy_version": "create_policy_version",
            "can_set_default_policy_version": "set_default_policy_version",
            "can_delete_or_detach_policy": "delete_or_detach_policy",
            "can_delete_permissions_boundary": "delete_permissions_boundary",
            "can_put_permissions_boundary": "put_permissions_boundary",
            "can_update_glue_dev_endpoint": "update_glue_dev_endpoint",
            "can_obtain_creds_via_cognito_identity_pool": "cognito_identity_pool_creds",
            "can_read_userdata": "read_userdata",
            "can_enum_backup": "enum_backup",
            "can_decode_key": "decode_key_account",
            "can_loot_snapshot": "loot_public_snapshot",
            "can_steal_imds_creds": "steal_imds_credentials",
            "can_ssm_session": "ssm_session",
            "can_snapshot_volume": "snapshot_volume_loot",
            "can_modify_userdata": "inject_userdata",
            "can_steal_lambda_creds": "steal_lambda_credentials",
            "can_steal_ecs_task_creds": "steal_ecs_task_credentials",
            "can_read_codebuild_env": "read_codebuild_env",
            "can_read_beanstalk_env": "read_beanstalk_env",
            "can_hijack_bedrock_agent": "hijack_bedrock_agent",
            "can_access_via_resource_policy": "access_via_resource_policy",
            "can_assume_via_oidc_misconfig": "assume_via_oidc_misconfig",
            "can_self_signup_cognito": "cognito_self_signup",
            "can_takeover_cloudfront_origin": "cloudfront_takeover",
            "can_create_eventbridge_rule": "eventbridge_rule_persistence",
            "can_get_federation_token": "get_federation_token",
            "can_create_codebuild_github_runner": "codebuild_github_runner_persistence",
            "can_create_rogue_oidc_persistence": "rogue_oidc_persistence",
            "can_create_roles_anywhere_persistence": "roles_anywhere_persistence",
            "can_modify_s3_acl_persistence": "s3_acl_persistence",
            "can_modify_guardduty_detector": "modify_guardduty_detector",
            "can_modify_guardduty_ip_trust_list": "modify_guardduty_ip_trust_list",
            "can_modify_guardduty_event_rules": "modify_guardduty_event_rules",
            "can_create_guardduty_suppression": "create_guardduty_suppression",
            "can_delete_guardduty_publishing_dest": "delete_guardduty_publishing_dest",
            "can_stop_cloudtrail": "stop_cloudtrail",
            "can_delete_cloudtrail": "delete_cloudtrail",
            "can_update_cloudtrail_config": "update_cloudtrail_config",
            "can_modify_cloudtrail_bucket_lifecycle": "modify_cloudtrail_bucket_lifecycle",
            "can_modify_cloudtrail_event_selectors": "modify_cloudtrail_event_selectors",
            "can_create_admin_user": "create_admin_user",
            "can_create_backdoor_role": "create_backdoor_role",
            "can_backdoor_lambda": "backdoor_lambda",
            "can_get_ec2_password_data": "get_ec2_password_data",
            "can_ec2_instance_connect": "ec2_instance_connect",
            "can_ec2_serial_console_ssh": "ec2_serial_console_ssh",
            "can_open_security_group_ingress": "open_security_group_ingress",
            "can_share_ami": "share_ami",
            "can_share_ebs_snapshot": "share_ebs_snapshot",
            "can_share_rds_snapshot": "share_rds_snapshot",
            "can_invoke_bedrock_model": "invoke_bedrock_model",
            "can_delete_dns_logs": "delete_dns_logs",
            "can_leave_organization": "leave_organization",
            "can_remove_vpc_flow_logs": "remove_vpc_flow_logs",
            "can_enumerate_ses": "enumerate_ses",
            "can_modify_sagemaker_lifecycle": "modify_sagemaker_lifecycle",
            "can_create_eks_access_entry": "create_eks_access_entry",
        }
        return mapping.get(edge_type, edge_type)

    @staticmethod
    def _calculate_pace(noise_level: str, step_index: int, total_steps: int) -> float:
        """Calculate delay before this step based on noise and position."""
        base_delays = {
            "silent": 1.0,
            "low": 3.0,
            "medium": 10.0,
            "high": 30.0,
            "critical": 60.0,
        }
        base = base_delays.get(noise_level, 10.0)

        # Increase delay for later steps (more cautious as we go deeper)
        position_factor = 1.0 + (step_index / max(total_steps, 1)) * 0.5
        return base * position_factor

    @staticmethod
    def _get_rollback_type(edge_type: str) -> str | None:
        """Determine if this action type supports rollback."""
        rollback_map = {
            "can_create_key": "delete_access_key",
            "can_attach_policy": "detach_policy",
            "can_put_policy": "delete_inline_policy",
            "can_modify_trust": "restore_trust_policy",
            "can_update_lambda": "restore_lambda_code",
            "can_modify_userdata": "restore_userdata",
        }
        return rollback_map.get(edge_type)
