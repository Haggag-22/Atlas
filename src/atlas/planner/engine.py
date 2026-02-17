"""
atlas.planner.engine
~~~~~~~~~~~~~~~~~~~~
Layer 2 orchestrator: the behavioral decision engine.

Consumes an EnvironmentModel (from Recon), builds the attack graph,
scores detection costs, analyzes guardrails, and produces an AttackPlan
for the Executor.

The PlannerEngine is the ONLY entry point into Layer 2.
"""

from __future__ import annotations

from typing import Any

import structlog

from atlas.core.config import AtlasConfig
from atlas.core.models import AttackPlan
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import Layer
from atlas.planner.attack_graph import AttackGraph, AttackGraphBuilder
from atlas.planner.detection import DetectionScorer
from atlas.planner.guardrail_analyzer import GuardrailAnalyzer
from atlas.planner.noise_budget import NoiseBudgetManager
from atlas.planner.path_finder import PathFinder
from atlas.planner.strategies.privesc import PrivilegeEscalationStrategy
from atlas.recon.engine import EnvironmentModel

logger = structlog.get_logger(__name__)


class PlannerEngine:
    """Layer 2 orchestrator.

    Transforms environment knowledge into actionable attack plans.
    """

    def __init__(
        self,
        config: AtlasConfig,
        recorder: TelemetryRecorder,
    ) -> None:
        self._config = config
        self._recorder = recorder

    def plan(self, env_model: EnvironmentModel) -> PlanResult:
        """Produce an attack plan from the environment model.

        This is the main entry point.  It:
          1. Builds the detection scorer (adjusted for logging posture)
          2. Constructs the attack graph
          3. Runs guardrail analysis
          4. Finds optimal paths
          5. Selects and applies a strategy
          6. Returns the plan + analysis artifacts
        """
        logger.info("planner_starting")
        self._recorder.record(
            layer=Layer.PLANNER,
            event_type="planning_start",
            details=env_model.summary(),
        )

        # ── Step 1: Build detection scorer ─────────────────────────
        scorer = DetectionScorer(env_model.logging_state)
        logger.info(
            "detection_scorer_initialized",
            cloudtrail_active=env_model.logging_state.has_active_cloudtrail,
            guardduty_enabled=env_model.logging_state.guardduty.is_enabled,
        )

        # ── Step 2: Build attack graph ─────────────────────────────
        builder = AttackGraphBuilder(
            env_model.graph,
            scorer,
            permission_map=env_model.permission_map,
        )
        attack_graph = builder.build()

        self._recorder.record(
            layer=Layer.PLANNER,
            event_type="attack_graph_built",
            details=attack_graph.summary(),
        )

        # ── Step 3: Guardrail analysis ─────────────────────────────
        guardrail_stats = {}
        if self._config.planner.enable_guardrail_analysis:
            analyzer = GuardrailAnalyzer(env_model.guardrail_state, env_model.graph)
            guardrail_stats = analyzer.analyze(attack_graph)

            self._recorder.record(
                layer=Layer.PLANNER,
                event_type="guardrail_analysis",
                details=guardrail_stats,
            )

        # ── Step 4: Initialize path finder ─────────────────────────
        path_finder = PathFinder(attack_graph)

        # ── Step 5: Initialize noise budget ────────────────────────
        noise_budget = NoiseBudgetManager(self._config.stealth.noise_budget)

        # ── Step 6: Determine source and target ────────────────────
        # Normalize assumed-role ARNs so they match graph nodes.
        # STS returns arn:aws:sts::...:assumed-role/Name/session
        # but the graph stores arn:aws:iam::...:role/Name.
        source_identity = env_model.metadata.caller_arn
        if ":assumed-role/" in source_identity:
            parts = source_identity.split(":")
            if len(parts) >= 6:
                resource = parts[5]
                role_parts = resource.split("/")
                role_name = role_parts[1] if len(role_parts) > 1 else role_parts[-1]
                account_id = parts[4]
                source_identity = f"arn:aws:iam::{account_id}:role/{role_name}"
                logger.debug(
                    "normalized_caller_arn",
                    raw=env_model.metadata.caller_arn,
                    normalized=source_identity,
                )
        target = self._determine_target(env_model, attack_graph, source_identity)

        logger.info(
            "planning_context",
            source=source_identity,
            target=target,
            noise_budget=noise_budget.total,
        )

        # ── Step 7: Run strategy ───────────────────────────────────
        strategy = PrivilegeEscalationStrategy()
        plan = strategy.evaluate(
            current_identity=source_identity,
            target=target,
            attack_graph=attack_graph,
            path_finder=path_finder,
            noise_budget=noise_budget,
            context={
                "env_model": env_model.summary(),
                "guardrails": guardrail_stats,
            },
        )

        # ── Step 8: Hypothesis testing (reachability analysis) ─────
        reachable = []
        if self._config.planner.enable_hypothesis_testing:
            reachable = path_finder.reachable_targets(
                source_identity, max_depth=self._config.planner.max_path_depth,
            )

        # ── Build result ───────────────────────────────────────────
        result = PlanResult(
            plan=plan,
            attack_graph=attack_graph,
            scorer=scorer,
            noise_budget=noise_budget,
            guardrail_stats=guardrail_stats,
            reachable_targets=reachable,
            source_identity=source_identity,
            target=target,
        )

        self._recorder.record(
            layer=Layer.PLANNER,
            event_type="planning_complete",
            details={
                "plan_id": plan.plan_id if plan else None,
                "strategy": plan.strategy if plan else None,
                "steps": len(plan.steps) if plan else 0,
                "detection_cost": plan.total_detection_cost if plan else 0,
                "reachable_targets": len(reachable),
            },
        )

        if plan:
            logger.info(
                "plan_ready",
                plan_id=plan.plan_id,
                strategy=plan.strategy,
                steps=len(plan.steps),
                detection_cost=f"{plan.total_detection_cost:.4f}",
                success_probability=f"{plan.estimated_success_probability:.4f}",
            )
        else:
            logger.debug("no_viable_plan_found")

        return result

    # ------------------------------------------------------------------
    # Target determination
    # ------------------------------------------------------------------

    # Edge types that represent credential pivots (you become the target)
    _PIVOT_EDGE_TYPES = {
        "can_assume", "can_create_key",
        "can_steal_imds_creds", "can_ssm_session",
    }

    def _determine_target(
        self,
        env_model: EnvironmentModel,
        attack_graph: AttackGraph | None = None,
        source_identity: str = "",
    ) -> str:
        """Determine the escalation target.

        Priority:
          1. Explicit target from config
          2. Privileged role reachable via any credential-pivot edge
          3. Any non-service-linked role reachable via credential pivot
          4. Any privileged-sounding role (even if not directly reachable)
          5. Any non-service-linked reachable role (via graph path)
          6. Any other user
          7. Account root (last resort fallback)
        """
        from atlas.core.types import NodeType

        # 1. Explicit target
        explicit = self._config.operation.target_privilege
        if explicit:
            return explicit

        roles = env_model.graph.nodes_of_type(NodeType.ROLE)

        privileged_keywords = (
            "admin", "administrator", "poweruser", "priv",
            "security", "full-access",
        )

        # 2. Look for privileged roles reachable via any credential-pivot edge
        if attack_graph and source_identity:
            for edge in attack_graph.edges:
                if (
                    edge.source_arn == source_identity
                    and edge.edge_type.value in self._PIVOT_EDGE_TYPES
                    and ":role/" in edge.target_arn
                ):
                    target_data = env_model.graph.get_node_data(edge.target_arn)
                    role_name = target_data.get("role_name", "").lower()
                    if any(kw in role_name for kw in privileged_keywords):
                        return edge.target_arn

        # 3. Any non-service-linked role reachable via credential pivot
        if attack_graph and source_identity:
            for edge in attack_graph.edges:
                if (
                    edge.source_arn == source_identity
                    and edge.edge_type.value in self._PIVOT_EDGE_TYPES
                    and ":role/" in edge.target_arn
                ):
                    target_data = env_model.graph.get_node_data(edge.target_arn)
                    if not target_data.get("is_service_linked", False):
                        return edge.target_arn

        # 4. Any privileged-sounding role (even if not directly reachable)
        for role_arn in roles:
            data = env_model.graph.get_node_data(role_arn)
            role_name = data.get("role_name", "").lower()
            if any(kw in role_name for kw in privileged_keywords):
                return role_arn

        # 5. Any non-service-linked reachable role (via graph path)
        if attack_graph and source_identity:
            import networkx as nx
            for role_arn in roles:
                data = env_model.graph.get_node_data(role_arn)
                if data.get("is_service_linked", False):
                    continue
                if attack_graph.raw.has_node(role_arn) and attack_graph.raw.has_node(source_identity):
                    try:
                        nx.shortest_path(attack_graph.raw, source_identity, role_arn)
                        return role_arn
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue

        # 6. Any other user
        users = env_model.graph.nodes_of_type(NodeType.USER)
        for user_arn in users:
            if user_arn != source_identity:
                return user_arn

        # 7. Fallback: account root
        return f"arn:aws:iam::{env_model.metadata.account_id}:root"


class PlanResult:
    """Complete output of the planning phase."""

    def __init__(
        self,
        *,
        plan: AttackPlan | None,
        attack_graph: AttackGraph,
        scorer: DetectionScorer,
        noise_budget: NoiseBudgetManager,
        guardrail_stats: dict[str, Any],
        reachable_targets: list[dict[str, Any]],
        source_identity: str,
        target: str,
    ) -> None:
        self.plan = plan
        self.attack_graph = attack_graph
        self.scorer = scorer
        self.noise_budget = noise_budget
        self.guardrail_stats = guardrail_stats
        self.reachable_targets = reachable_targets
        self.source_identity = source_identity
        self.target = target

    def summary(self) -> dict[str, Any]:
        return {
            "Plan Found": self.plan is not None,
            "Source Identity": self.source_identity.split("/")[-1],
            "Target": self.target.split("/")[-1] if "/" in self.target else self.target.split(":")[-1],
            "Strategy": self.plan.strategy if self.plan else "—",
            "Steps": len(self.plan.steps) if self.plan else 0,
            "Total Detection Cost": self.plan.total_detection_cost if self.plan else 0,
            "Success Probability": self.plan.estimated_success_probability if self.plan else 0,
            "Reachable Targets": len(self.reachable_targets),
        }
