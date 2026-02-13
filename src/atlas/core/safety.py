"""
atlas.core.safety
~~~~~~~~~~~~~~~~~
Hard safety guardrails that CANNOT be bypassed by any layer.

Every AWS API call passes through ``SafetyGate.check()`` before execution.
The gate can block, warn, or allow.  It also tracks noise budget consumption.

Design rules:
  - Safety is checked in the Executor, NEVER skipped.
  - Rollback registry is populated by the Executor after each mutating action.
  - Emergency stop kills all pending work immediately.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

import structlog

from atlas.core.config import SafetyConfig

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Safety check result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SafetyVerdict:
    """Result of a safety check."""
    allowed: bool
    reason: str = ""
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rollback entry
# ---------------------------------------------------------------------------
@dataclass
class RollbackEntry:
    """Describes how to undo a mutating action."""
    action_id: str
    description: str
    rollback_fn: Callable[..., Any] | None = None
    rollback_params: dict[str, Any] = field(default_factory=dict)
    executed_at: str = ""


# ---------------------------------------------------------------------------
# Safety gate
# ---------------------------------------------------------------------------
class SafetyGate:
    """Centralised safety enforcement.

    Instantiated once per operation and threaded through all layers.
    """

    def __init__(self, config: SafetyConfig) -> None:
        self._config = config
        self._noise_spent: float = 0.0
        self._emergency_stop = asyncio.Event()
        self._rollback_stack: list[RollbackEntry] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Pre-action checks
    # ------------------------------------------------------------------
    def check_account(self, account_id: str) -> SafetyVerdict:
        """Verify the target account is in the allowlist."""
        if not self._config.allowed_account_ids:
            return SafetyVerdict(
                allowed=False,
                reason="No allowed_account_ids configured -- refusing to proceed.",
            )
        if account_id not in self._config.allowed_account_ids:
            return SafetyVerdict(
                allowed=False,
                reason=f"Account {account_id} is not in the allowlist.",
            )
        return SafetyVerdict(allowed=True)

    def check_region(self, region: str) -> SafetyVerdict:
        if region not in self._config.allowed_regions:
            return SafetyVerdict(
                allowed=False,
                reason=f"Region {region} is not in the allowlist.",
            )
        return SafetyVerdict(allowed=True)

    def check_noise_budget(self, detection_cost: float) -> SafetyVerdict:
        """Check whether spending *detection_cost* would exceed the budget."""
        projected = self._noise_spent + detection_cost
        ceiling = self._config.max_noise_budget
        if projected > ceiling:
            return SafetyVerdict(
                allowed=False,
                reason=(
                    f"Noise budget exceeded: {projected:.2f} > {ceiling:.2f} "
                    f"(current={self._noise_spent:.2f}, action={detection_cost:.2f})"
                ),
            )
        warnings: list[str] = []
        if projected > ceiling * 0.8:
            warnings.append(
                f"Approaching noise ceiling: {projected:.2f}/{ceiling:.2f} ({projected/ceiling:.0%})"
            )
        return SafetyVerdict(allowed=True, warnings=warnings)

    def check_dry_run(self) -> SafetyVerdict:
        if self._config.dry_run:
            return SafetyVerdict(allowed=False, reason="Dry-run mode active.")
        return SafetyVerdict(allowed=True)

    def full_check(
        self,
        *,
        account_id: str,
        region: str,
        detection_cost: float = 0.0,
        is_mutating: bool = False,
    ) -> SafetyVerdict:
        """Run all safety checks.  Returns first failure or success."""
        if self._emergency_stop.is_set():
            return SafetyVerdict(allowed=False, reason="Emergency stop is active.")

        checks = [
            self.check_account(account_id),
            self.check_region(region),
            self.check_noise_budget(detection_cost),
        ]
        if is_mutating:
            checks.append(self.check_dry_run())

        all_warnings: list[str] = []
        for verdict in checks:
            all_warnings.extend(verdict.warnings)
            if not verdict.allowed:
                return SafetyVerdict(
                    allowed=False,
                    reason=verdict.reason,
                    warnings=all_warnings,
                )

        return SafetyVerdict(allowed=True, warnings=all_warnings)

    # ------------------------------------------------------------------
    # Noise budget tracking
    # ------------------------------------------------------------------
    def spend_noise(self, cost: float) -> None:
        """Record that *cost* detection units were consumed."""
        with self._lock:
            self._noise_spent += cost
            logger.debug(
                "noise_budget_update",
                spent=cost,
                total=self._noise_spent,
                ceiling=self._config.max_noise_budget,
            )

    @property
    def noise_spent(self) -> float:
        return self._noise_spent

    @property
    def noise_remaining(self) -> float:
        return max(0.0, self._config.max_noise_budget - self._noise_spent)

    # ------------------------------------------------------------------
    # Emergency stop
    # ------------------------------------------------------------------
    def trigger_emergency_stop(self, reason: str = "") -> None:
        logger.critical("emergency_stop_triggered", reason=reason)
        self._emergency_stop.set()

    @property
    def is_stopped(self) -> bool:
        return self._emergency_stop.is_set()

    # ------------------------------------------------------------------
    # Rollback registry
    # ------------------------------------------------------------------
    def register_rollback(self, entry: RollbackEntry) -> None:
        with self._lock:
            self._rollback_stack.append(entry)
            logger.info("rollback_registered", action_id=entry.action_id, desc=entry.description)

    async def execute_rollbacks(self) -> list[dict[str, Any]]:
        """Execute all rollbacks in reverse order (LIFO).  Returns results."""
        results: list[dict[str, Any]] = []
        while self._rollback_stack:
            entry = self._rollback_stack.pop()
            try:
                if entry.rollback_fn is not None:
                    if asyncio.iscoroutinefunction(entry.rollback_fn):
                        await entry.rollback_fn(**entry.rollback_params)
                    else:
                        entry.rollback_fn(**entry.rollback_params)
                    results.append({"action_id": entry.action_id, "status": "rolled_back"})
                    logger.info("rollback_executed", action_id=entry.action_id)
                else:
                    results.append({"action_id": entry.action_id, "status": "no_rollback_fn"})
            except Exception as exc:
                results.append({
                    "action_id": entry.action_id,
                    "status": "rollback_failed",
                    "error": str(exc),
                })
                logger.error("rollback_failed", action_id=entry.action_id, error=str(exc))
        return results

    @property
    def rollback_count(self) -> int:
        return len(self._rollback_stack)


# ---------------------------------------------------------------------------
# Lab banner
# ---------------------------------------------------------------------------
LAB_BANNER = """
╔══════════════════════════════════════════════════════════════════════════╗
║  ATLAS v2 — AWS Cloud Adversary Emulation Platform                     ║
║                                                                        ║
║  FOR AUTHORIZED USE ONLY.  You are responsible for compliance           ║
║  with AWS ToS, applicable laws, and your organization's policies.      ║
║                                                                        ║
║  This tool performs real API calls against AWS accounts.                ║
║  Ensure you have explicit written authorization.                       ║
╚══════════════════════════════════════════════════════════════════════════╝
""".strip()
