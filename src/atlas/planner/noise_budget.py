"""
atlas.planner.noise_budget
~~~~~~~~~~~~~~~~~~~~~~~~~~
Tracks cumulative detection exposure across an operation.

The noise budget is a finite resource.  Every action spends some of it.
When the budget is exhausted, the planner must stop proposing new actions
or switch to lower-noise alternatives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class NoiseLedgerEntry:
    """Record of noise spent by a single action."""
    action_id: str
    api_action: str
    cost: float
    cumulative: float
    timestamp: str = ""


class NoiseBudgetManager:
    """Manages the operation's noise budget.

    The planner consults this before proposing actions.
    The executor reports actual spend after each action.
    """

    def __init__(self, total_budget: float) -> None:
        self._total = total_budget
        self._spent: float = 0.0
        self._ledger: list[NoiseLedgerEntry] = []

    @property
    def total(self) -> float:
        return self._total

    @property
    def spent(self) -> float:
        return self._spent

    @property
    def remaining(self) -> float:
        return max(0.0, self._total - self._spent)

    @property
    def utilization(self) -> float:
        """Fraction of budget consumed (0.0 to 1.0+)."""
        return self._spent / self._total if self._total > 0 else 0.0

    @property
    def is_exhausted(self) -> bool:
        return self._spent >= self._total

    def can_afford(self, cost: float) -> bool:
        """Check if spending *cost* would stay within budget."""
        return (self._spent + cost) <= self._total

    def spend(self, action_id: str, api_action: str, cost: float) -> bool:
        """Record noise spend.  Returns False if budget exceeded."""
        self._spent += cost
        self._ledger.append(NoiseLedgerEntry(
            action_id=action_id,
            api_action=api_action,
            cost=cost,
            cumulative=self._spent,
        ))

        if self.is_exhausted:
            logger.warning(
                "noise_budget_exhausted",
                spent=self._spent,
                total=self._total,
                last_action=api_action,
            )
            return False

        if self.utilization > 0.8:
            logger.warning(
                "noise_budget_high",
                utilization=f"{self.utilization:.0%}",
                remaining=f"{self.remaining:.2f}",
            )

        return True

    def project_spend(self, costs: list[float]) -> dict[str, Any]:
        """Project what happens if we spend a sequence of costs."""
        projected = self._spent
        steps: list[dict[str, Any]] = []
        for i, cost in enumerate(costs):
            projected += cost
            steps.append({
                "step": i,
                "cost": cost,
                "cumulative": round(projected, 4),
                "within_budget": projected <= self._total,
            })
        return {
            "current_spent": self._spent,
            "projected_total": round(projected, 4),
            "within_budget": projected <= self._total,
            "steps": steps,
        }

    def get_ledger(self) -> list[dict[str, Any]]:
        return [
            {"action_id": e.action_id, "api_action": e.api_action,
             "cost": e.cost, "cumulative": e.cumulative}
            for e in self._ledger
        ]

    def summary(self) -> dict[str, Any]:
        return {
            "total_budget": self._total,
            "spent": round(self._spent, 4),
            "remaining": round(self.remaining, 4),
            "utilization": f"{self.utilization:.1%}",
            "actions_recorded": len(self._ledger),
        }
