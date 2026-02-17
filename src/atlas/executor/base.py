"""
atlas.executor.base
~~~~~~~~~~~~~~~~~~~
Abstract base class for executor actions..

An action's job:
  1. Receive a PlannedAction from the planner.
  2. Execute the AWS API call(s).
  3. Return an ActionResult with outcomes and any new discoveries.
  4. Register rollback if the action was mutating.

An action MUST NOT:
  - Make decisions about what to do next (that's the planner's job).
  - Skip safety checks (the engine handles those).
  - Import from the planner layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import aioboto3

from atlas.core.config import AtlasConfig
from atlas.core.models import ActionResult, PlannedAction
from atlas.core.safety import RollbackEntry, SafetyGate
from atlas.core.telemetry import TelemetryRecorder


class BaseAction(ABC):
    """Abstract base for executor actions."""

    def __init__(
        self,
        session: aioboto3.Session,
        config: AtlasConfig,
        safety: SafetyGate,
        recorder: TelemetryRecorder,
    ) -> None:
        self._session = session
        self._config = config
        self._safety = safety
        self._recorder = recorder

    @property
    @abstractmethod
    def action_type(self) -> str:
        """Matches PlannedAction.action_type, e.g. 'assume_role'."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @property
    def is_mutating(self) -> bool:
        """Whether this action modifies AWS state."""
        return True

    @abstractmethod
    async def execute(self, planned: PlannedAction) -> ActionResult:
        """Execute the planned action and return results."""
        ...

    def get_rollback_entry(
        self,
        planned: PlannedAction,
        result: ActionResult,
    ) -> RollbackEntry | None:
        """Return a RollbackEntry if this action supports rollback.

        Override in subclasses that support rollback.
        """
        return None
