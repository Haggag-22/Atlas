"""
atlas.planner.guardrail_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Evaluates whether attack edges are blocked by guardrails:
  - SCPs (Service Control Policies)
  - Permission boundaries
  - Conditional IAM policies (MFA, source IP, etc.)

The analyzer annotates edges with guardrail_status:
  - "clear"     — no guardrail blocks this action
  - "blocked"   — an SCP or boundary explicitly denies this action
  - "uncertain" — conditions exist that may block (MFA, IP, etc.)
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.models import AttackEdge, GuardrailState
from atlas.core.types import NodeType
from atlas.core.graph import EnvironmentGraph
from atlas.planner.attack_graph import AttackGraph

logger = structlog.get_logger(__name__)


class GuardrailAnalyzer:
    """Evaluate guardrails against attack graph edges."""

    def __init__(
        self,
        guardrail_state: GuardrailState,
        env_graph: EnvironmentGraph,
    ) -> None:
        self._guardrails = guardrail_state
        self._env = env_graph
        # Pre-compile SCP deny sets for fast lookup
        self._scp_deny_actions = self._compile_scp_denies()
        self._boundary_allow_actions = self._compile_boundary_allows()

    def analyze(self, attack_graph: AttackGraph) -> dict[str, Any]:
        """Annotate all edges in the attack graph with guardrail status.

        Returns stats about how many edges were blocked/uncertain.
        """
        stats = {"total": 0, "clear": 0, "blocked": 0, "uncertain": 0}

        for edge in attack_graph.edges:
            status = self._evaluate_edge(edge)
            # AttackEdge is frozen, so we update the graph edge directly
            g = attack_graph.raw
            if g.has_edge(edge.source_arn, edge.target_arn):
                g.edges[edge.source_arn, edge.target_arn]["guardrail_status"] = status
                # Reduce success probability for blocked/uncertain edges
                if status == "blocked":
                    g.edges[edge.source_arn, edge.target_arn]["success_probability"] = 0.0
                elif status == "uncertain":
                    current = g.edges[edge.source_arn, edge.target_arn]["success_probability"]
                    g.edges[edge.source_arn, edge.target_arn]["success_probability"] = current * 0.3

            stats["total"] += 1
            stats[status] += 1

        logger.info("guardrail_analysis_complete", **stats)
        return stats

    # ------------------------------------------------------------------
    # Edge evaluation
    # ------------------------------------------------------------------
    def _evaluate_edge(self, edge: AttackEdge) -> str:
        """Determine guardrail status for a single edge."""
        for action in edge.api_actions:
            # Check SCPs
            if self._is_scp_denied(action, edge.target_arn):
                return "blocked"

            # Check permission boundary on the source identity
            if self._is_boundary_blocked(action, edge.source_arn):
                return "blocked"

            # Check permission boundary on the target (for assumption)
            if self._is_boundary_blocked(action, edge.target_arn):
                return "blocked"

        # Check conditions
        if edge.conditions:
            if self._has_blocking_conditions(edge.conditions):
                return "uncertain"

        # Check MFA enforcement on source
        if edge.source_arn in self._guardrails.mfa_enforcement:
            if self._guardrails.mfa_enforcement[edge.source_arn]:
                return "uncertain"

        return "clear"

    # ------------------------------------------------------------------
    # SCP checking
    # ------------------------------------------------------------------
    def _compile_scp_denies(self) -> set[str]:
        """Extract all explicitly denied actions from SCPs."""
        denied: set[str] = set()
        for scp in self._guardrails.scps:
            doc = scp.policy_document
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Deny":
                    continue
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                denied.update(actions)
        return denied

    def _is_scp_denied(self, action: str, target_arn: str) -> bool:
        """Check if an action is explicitly denied by any SCP."""
        if action in self._scp_deny_actions:
            return True
        # Wildcard check
        for denied in self._scp_deny_actions:
            if denied == "*":
                return True
            if denied.endswith("*"):
                if action.startswith(denied[:-1]):
                    return True
        return False

    # ------------------------------------------------------------------
    # Permission boundary checking
    # ------------------------------------------------------------------
    def _compile_boundary_allows(self) -> dict[str, set[str]]:
        """For each identity with a boundary, extract the allowed actions."""
        boundaries: dict[str, set[str]] = {}
        for identity_arn, boundary_arn in self._guardrails.permission_boundaries.items():
            # Look up the boundary policy in the graph
            if self._env.has_node(boundary_arn):
                data = self._env.get_node_data(boundary_arn)
                doc = data.get("policy_document", {})
                allowed = self._extract_allowed_actions(doc)
                boundaries[identity_arn] = allowed
        return boundaries

    def _is_boundary_blocked(self, action: str, identity_arn: str) -> bool:
        """Check if a permission boundary blocks an action for an identity."""
        allowed = self._boundary_allow_actions.get(identity_arn)
        if allowed is None:
            return False  # no boundary = no restriction

        # Boundary is a whitelist — if action isn't in it, it's blocked
        if action in allowed:
            return False
        # Check wildcards
        for a in allowed:
            if a == "*":
                return False
            if a.endswith("*") and action.startswith(a[:-1]):
                return False
        return True

    # ------------------------------------------------------------------
    # Condition analysis
    # ------------------------------------------------------------------
    @staticmethod
    def _has_blocking_conditions(conditions: dict[str, Any]) -> bool:
        """Check if conditions contain potentially blocking constraints."""
        blocking_keys = {
            "aws:MultiFactorAuthPresent",
            "aws:MultiFactorAuthAge",
            "aws:SourceIp",
            "aws:SourceVpce",
            "aws:PrincipalOrgID",
            "sts:ExternalId",
        }
        for op, values in conditions.items():
            if isinstance(values, dict):
                for key in values:
                    if key in blocking_keys:
                        return True
        return False

    @staticmethod
    def _extract_allowed_actions(doc: dict[str, Any]) -> set[str]:
        """Extract all allowed actions from a policy document."""
        allowed: set[str] = set()
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            allowed.update(actions)
        return allowed
