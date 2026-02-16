"""
atlas.recon.auth.guardrail
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Discovers guardrails: SCPs, permission boundaries, conditional policies.

This data is critical for the planner's guardrail analyzer — it determines
which attack paths are feasible vs. blocked.
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import GuardrailState, SCPPolicy
from atlas.core.types import NodeType
from atlas.knowledge.api_profiles import get_detection_score
from atlas.recon.base import BaseCollector
from atlas.utils.aws import safe_api_call

logger = structlog.get_logger(__name__)


class GuardrailCollector(BaseCollector):
    """Discover SCPs, permission boundaries, and conditional policy patterns."""

    @property
    def collector_id(self) -> str:
        return "guardrail"

    @property
    def description(self) -> str:
        return "Discover SCPs, permission boundaries, MFA enforcement, IP restrictions."

    @property
    def required_permissions(self) -> list[str]:
        return [
            "organizations:ListPolicies",
            "organizations:DescribePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
        ]

    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        stats = {
            "scps_found": 0,
            "permission_boundaries": 0,
            "mfa_enforced_identities": 0,
            "ip_restrictions": 0,
        }

        guardrail_state = GuardrailState()

        # ── SCPs (requires Organizations access — may fail gracefully) ──
        scps = await self._collect_scps()
        guardrail_state.scps = scps
        stats["scps_found"] = len(scps)

        # ── Permission boundaries from graph ───────────────────────
        boundaries = self._collect_permission_boundaries()
        guardrail_state.permission_boundaries = boundaries
        stats["permission_boundaries"] = len(boundaries)

        # ── MFA enforcement detection ──────────────────────────────
        mfa_map = self._detect_mfa_enforcement()
        guardrail_state.mfa_enforcement = mfa_map
        stats["mfa_enforced_identities"] = sum(1 for v in mfa_map.values() if v)

        # ── IP restrictions detection ──────────────────────────────
        ip_restrictions = self._detect_ip_restrictions()
        guardrail_state.ip_restrictions = ip_restrictions
        stats["ip_restrictions"] = len(ip_restrictions)

        # Store guardrail state on the account node
        acct_arn = f"arn:aws:iam::{account_id}:root"
        if self._graph.has_node(acct_arn):
            node_data = self._graph.get_node_data(acct_arn)
            node_data["guardrail_state"] = guardrail_state.model_dump()

        logger.info("guardrail_collection_complete", **stats)
        return {**stats, "guardrail_state": guardrail_state.model_dump()}

    # ------------------------------------------------------------------
    # SCP collection
    # ------------------------------------------------------------------
    async def _collect_scps(self) -> list[SCPPolicy]:
        """Try to list SCPs via Organizations API.  Fails gracefully."""
        scps: list[SCPPolicy] = []
        try:
            async with self._session.client("organizations") as org:
                resp = await safe_api_call(
                    org.list_policies(Filter="SERVICE_CONTROL_POLICY"),
                    default=None,
                )
                self._record("organizations:ListPolicies",
                             detection_cost=get_detection_score("organizations:ListPolicies"))

                if not resp:
                    logger.info("scp_access_denied_or_not_in_org")
                    return scps

                for policy_summary in resp.get("Policies", []):
                    policy_id = policy_summary["Id"]
                    detail = await safe_api_call(
                        org.describe_policy(PolicyId=policy_id),
                        default=None,
                    )
                    self._record("organizations:DescribePolicy",
                                 detection_cost=get_detection_score("organizations:DescribePolicy"))

                    if detail:
                        policy_detail = detail.get("Policy", {})
                        content = policy_detail.get("Content", "{}")
                        import json
                        try:
                            doc = json.loads(content) if isinstance(content, str) else content
                        except json.JSONDecodeError:
                            doc = {}

                        scps.append(SCPPolicy(
                            policy_id=policy_id,
                            policy_name=policy_summary.get("Name", ""),
                            description=policy_summary.get("Description", ""),
                            policy_document=doc,
                        ))
        except Exception as exc:
            logger.info("scp_collection_skipped", reason=str(exc))

        return scps

    # ------------------------------------------------------------------
    # Permission boundary detection (from graph data)
    # ------------------------------------------------------------------
    def _collect_permission_boundaries(self) -> dict[str, str]:
        """Scan graph nodes for permission boundary annotations."""
        boundaries: dict[str, str] = {}
        for node_type in (NodeType.USER, NodeType.ROLE):
            for arn in self._graph.nodes_of_type(node_type):
                data = self._graph.get_node_data(arn)
                pb_arn = data.get("permission_boundary_arn")
                if pb_arn:
                    boundaries[arn] = pb_arn
        return boundaries

    # ------------------------------------------------------------------
    # MFA enforcement detection (from policy documents in graph)
    # ------------------------------------------------------------------
    def _detect_mfa_enforcement(self) -> dict[str, bool]:
        """Check policy documents for MFA conditions."""
        mfa_map: dict[str, bool] = {}
        policy_nodes = self._graph.nodes_of_type(NodeType.POLICY)
        for policy_arn in policy_nodes:
            data = self._graph.get_node_data(policy_arn)
            doc = data.get("policy_document", {})
            if self._has_mfa_condition(doc):
                attached_to = data.get("attached_to", "")
                if attached_to:
                    mfa_map[attached_to] = True
        return mfa_map

    @staticmethod
    def _has_mfa_condition(policy_doc: dict[str, Any]) -> bool:
        """Check if a policy document has MFA conditions."""
        for stmt in policy_doc.get("Statement", []):
            conditions = stmt.get("Condition", {})
            for cond_op, cond_values in conditions.items():
                if isinstance(cond_values, dict):
                    for key in cond_values:
                        if "MultiFactorAuth" in key or "mfa" in key.lower():
                            return True
        return False

    # ------------------------------------------------------------------
    # IP restriction detection
    # ------------------------------------------------------------------
    def _detect_ip_restrictions(self) -> list[dict[str, Any]]:
        """Detect policies with IP-based conditions (aws:SourceIp)."""
        restrictions: list[dict[str, Any]] = []
        policy_nodes = self._graph.nodes_of_type(NodeType.POLICY)
        for policy_arn in policy_nodes:
            data = self._graph.get_node_data(policy_arn)
            doc = data.get("policy_document", {})
            for stmt in doc.get("Statement", []):
                conditions = stmt.get("Condition", {})
                for cond_op, cond_values in conditions.items():
                    if isinstance(cond_values, dict):
                        for key, val in cond_values.items():
                            if "SourceIp" in key or "sourceip" in key.lower():
                                restrictions.append({
                                    "policy": policy_arn,
                                    "condition": cond_op,
                                    "key": key,
                                    "values": val,
                                    "statement_effect": stmt.get("Effect", ""),
                                })
        return restrictions
