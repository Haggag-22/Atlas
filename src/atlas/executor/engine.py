"""
atlas.executor.engine
~~~~~~~~~~~~~~~~~~~~~
Layer 3 orchestrator: controlled, detection-aware execution.

The ExecutorEngine:
  1. Receives an AttackPlan from the Planner.
  2. Executes each PlannedAction in order.
  3. Enforces safety checks before every action.
  4. Applies pace control (stealth timing).
  5. Records telemetry and rollback entries.
  6. Feeds results back for model updates.

The ExecutorEngine does NOT decide what to do — it only does what
the Planner tells it to do, with safety and stealth constraints.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from atlas.core.config import AtlasConfig
from atlas.core.models import ActionResult, AttackPlan, PlannedAction
from atlas.core.safety import SafetyGate
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import ActionStatus, Layer, NoiseLevel
from atlas.executor.actions.iam import (
    AttachPolicyAction,
    CreateAccessKeyAction,
    PutInlinePolicyAction,
)
from atlas.executor.actions.sts import AssumeRoleAction
from atlas.executor.base import BaseAction
from atlas.executor.pace import PaceController
from atlas.executor.session import SessionManager

logger = structlog.get_logger(__name__)


class ExecutorEngine:
    """Layer 3 orchestrator.

    Executes planned actions with safety checks and stealth pacing.
    """

    # Action registry: maps action_type to action class
    ACTION_REGISTRY: dict[str, type[BaseAction]] = {
        "assume_role": AssumeRoleAction,
        "create_access_key": CreateAccessKeyAction,
        "attach_policy": AttachPolicyAction,
        "put_inline_policy": PutInlinePolicyAction,
    }

    def __init__(
        self,
        config: AtlasConfig,
        safety: SafetyGate,
        recorder: TelemetryRecorder,
        session_manager: SessionManager,
    ) -> None:
        self._config = config
        self._safety = safety
        self._recorder = recorder
        self._session_mgr = session_manager
        self._pace = PaceController(config.stealth)
        self._results: list[ActionResult] = []

    async def execute(self, plan: AttackPlan) -> ExecutionReport:
        """Execute all steps in the attack plan.

        Returns an ExecutionReport with results and feedback.
        """
        logger.info(
            "executor_starting",
            plan_id=plan.plan_id,
            steps=len(plan.steps),
            strategy=plan.strategy,
        )

        self._recorder.record(
            layer=Layer.EXECUTOR,
            event_type="execution_start",
            details={
                "plan_id": plan.plan_id,
                "steps": len(plan.steps),
                "total_detection_cost": plan.total_detection_cost,
            },
        )

        start_time = time.monotonic()
        self._results = []

        for step in plan.steps:
            # ── Check emergency stop ──────────────────────────────
            if self._safety.is_stopped:
                logger.warning("emergency_stop_active")
                self._results.append(ActionResult(
                    action_id=step.action_id,
                    status=ActionStatus.BLOCKED.value,
                    error="Emergency stop active.",
                ))
                break

            # ── Execute step ──────────────────────────────────────
            result = await self._execute_step(step)
            self._results.append(result)

            # ── Handle failure ────────────────────────────────────
            if result.status in (ActionStatus.FAILURE.value, ActionStatus.BLOCKED.value):
                logger.warning(
                    "step_failed",
                    action_id=step.action_id,
                    status=result.status,
                    error=result.error,
                )
                # Don't abort the whole plan on permission denied — the planner
                # may have fallback steps.  Only abort on safety blocks.
                if result.status == ActionStatus.BLOCKED.value:
                    break

            # ── Update session if we pivoted ──────────────────────
            if result.status == ActionStatus.SUCCESS.value:
                self._update_session(step, result)

        elapsed = time.monotonic() - start_time

        report = ExecutionReport(
            plan_id=plan.plan_id,
            results=self._results,
            total_time_seconds=elapsed,
            total_delay_seconds=self._pace.total_delay_seconds,
            rollback_count=self._safety.rollback_count,
        )

        self._recorder.record(
            layer=Layer.EXECUTOR,
            event_type="execution_complete",
            details=report.summary(),
        )

        logger.info("executor_complete", **report.summary())
        return report

    # ------------------------------------------------------------------
    # Single step execution
    # ------------------------------------------------------------------
    async def _execute_step(self, step: PlannedAction) -> ActionResult:
        """Execute a single PlannedAction with safety and pacing."""

        # ── Safety checks ─────────────────────────────────────────
        account_id = self._extract_account_id(step.target_arn)
        region = self._config.aws.region

        action_cls = self.ACTION_REGISTRY.get(step.action_type)
        is_mutating = action_cls.is_mutating.fget(None) if action_cls else True  # type: ignore

        verdict = self._safety.full_check(
            account_id=account_id,
            region=region,
            detection_cost=step.detection_cost,
            is_mutating=is_mutating,
        )

        if not verdict.allowed:
            logger.warning(
                "safety_blocked",
                action_id=step.action_id,
                reason=verdict.reason,
            )
            return ActionResult(
                action_id=step.action_id,
                status=ActionStatus.BLOCKED.value,
                error=f"Safety check failed: {verdict.reason}",
            )

        for warning in verdict.warnings:
            logger.warning("safety_warning", warning=warning)

        # ── Pace control ──────────────────────────────────────────
        await self._pace.wait_before_action(
            noise_level=step.noise_level,
            pace_hint_seconds=step.pace_hint_seconds,
        )

        # ── Resolve action handler ────────────────────────────────
        if not action_cls:
            return ActionResult(
                action_id=step.action_id,
                status=ActionStatus.FAILURE.value,
                error=f"Unknown action type: {step.action_type}",
            )

        # ── Execute ───────────────────────────────────────────────
        session = self._session_mgr.get_current_session()
        action = action_cls(
            session=session,
            config=self._config,
            safety=self._safety,
            recorder=self._recorder,
        )

        try:
            result = await action.execute(step)
        except Exception as exc:
            logger.error(
                "action_exception",
                action_id=step.action_id,
                error=str(exc),
            )
            result = ActionResult(
                action_id=step.action_id,
                status=ActionStatus.FAILURE.value,
                error=str(exc),
            )

        # ── Post-execution bookkeeping ────────────────────────────
        # Record noise spend
        self._safety.spend_noise(result.actual_detection_cost)

        # Register rollback if applicable
        rollback = action.get_rollback_entry(step, result)
        if rollback and self._config.safety.enable_rollback:
            self._safety.register_rollback(rollback)

        return result

    # ------------------------------------------------------------------
    # Session updates
    # ------------------------------------------------------------------
    def _update_session(self, step: PlannedAction, result: ActionResult) -> None:
        """Update the session manager after a successful pivot action."""
        if step.action_type == "assume_role":
            self._session_mgr.add_assumed_role(
                role_arn=result.outputs.get("assumed_role_arn", step.target_arn),
                access_key_id=result.outputs.get("access_key_id", ""),
                secret_access_key=result.outputs.get("secret_access_key", ""),
                session_token=result.outputs.get("session_token", ""),
                expiration=result.outputs.get("expiration", ""),
            )
        elif step.action_type == "create_access_key":
            self._session_mgr.add_access_key(
                user_arn=step.target_arn,
                access_key_id=result.outputs.get("access_key_id", ""),
                secret_access_key=result.outputs.get("secret_access_key", ""),
            )

    @staticmethod
    def _extract_account_id(arn: str) -> str:
        """Extract 12-digit account ID from an ARN."""
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4]
        return ""


class ExecutionReport:
    """Summary of an execution run."""

    def __init__(
        self,
        *,
        plan_id: str,
        results: list[ActionResult],
        total_time_seconds: float,
        total_delay_seconds: float,
        rollback_count: int,
    ) -> None:
        self.plan_id = plan_id
        self.results = results
        self.total_time_seconds = total_time_seconds
        self.total_delay_seconds = total_delay_seconds
        self.rollback_count = rollback_count

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results if r.status == ActionStatus.SUCCESS.value)

    @property
    def failure_count(self) -> int:
        return sum(1 for r in self.results if r.status in (ActionStatus.FAILURE.value, ActionStatus.BLOCKED.value))

    @property
    def all_discoveries(self) -> list[dict[str, Any]]:
        discoveries: list[dict[str, Any]] = []
        for r in self.results:
            discoveries.extend(r.new_discoveries)
        return discoveries

    def summary(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "total_steps": len(self.results),
            "success": self.success_count,
            "failures": self.failure_count,
            "total_time": f"{self.total_time_seconds:.1f}s",
            "stealth_delay": f"{self.total_delay_seconds:.1f}s",
            "rollbacks_registered": self.rollback_count,
            "discoveries": len(self.all_discoveries),
        }
