"""
atlas.planner.strategies.base
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Base class for attack strategies.

A strategy evaluates the current state and returns candidate attack plans.
The planner engine selects the best strategy based on configuration and context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from atlas.core.models import AttackPlan
from atlas.planner.attack_graph import AttackGraph
from atlas.planner.noise_budget import NoiseBudgetManager
from atlas.planner.path_finder import PathFinder


class BaseStrategy(ABC):
    """Abstract base for attack strategies."""

    @property
    @abstractmethod
    def strategy_id(self) -> str:
        """Unique identifier."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @abstractmethod
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
        """Evaluate this strategy and return a plan, or None if not applicable."""
        ...
