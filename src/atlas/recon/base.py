"""
atlas.recon.base
~~~~~~~~~~~~~~~~
Abstract base class for all recon collectors.

A collector's job:
  1. Make read-only AWS API calls.
  2. Convert raw responses into typed core models.
  3. Add nodes and edges to the EnvironmentGraph.
  4. Record telemetry for every API call made.

A collector MUST NOT:
  - Execute any write/mutating API calls.
  - Make decisions about attack paths.
  - Import anything from the planner or executor layers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import aioboto3
import structlog

from atlas.core.config import AtlasConfig
from atlas.core.graph import EnvironmentGraph
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import Layer

if TYPE_CHECKING:
    from atlas.core.permission_map import PermissionMap

logger = structlog.get_logger(__name__)


class BaseCollector(ABC):
    """Abstract base for recon collectors."""

    def __init__(
        self,
        session: aioboto3.Session,
        config: AtlasConfig,
        graph: EnvironmentGraph,
        recorder: TelemetryRecorder,
        *,
        permission_map: PermissionMap | None = None,
        caller_arn: str = "",
    ) -> None:
        self._session = session
        self._config = config
        self._graph = graph
        self._recorder = recorder
        self._permission_map = permission_map
        self._caller_arn = caller_arn

    @property
    @abstractmethod
    def collector_id(self) -> str:
        """Unique identifier, e.g. 'identity', 'policy'."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @property
    def required_permissions(self) -> list[str]:
        """IAM actions this collector needs (documentation only)."""
        return []

    @abstractmethod
    async def collect(self, account_id: str, region: str) -> dict[str, Any]:
        """Run collection.  Populate the graph.  Return summary stats."""
        ...

    # ------------------------------------------------------------------
    # Helpers available to all collectors
    # ------------------------------------------------------------------
    def _caller_has(self, action: str) -> bool:
        """Check if the caller has a specific IAM permission.

        Returns ``True`` (optimistic) when no PermissionMap is
        available so that collectors fall back to trying the API and
        handling ``AccessDenied`` via ``safe_api_call()``.
        """
        if not self._permission_map or not self._caller_arn:
            return True
        return self._permission_map.identity_has_permission(
            self._caller_arn, action,
        )

    def _record(
        self,
        action: str,
        *,
        status: str = "success",
        target_arn: str = "",
        detection_cost: float = 0.0,
        error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Shorthand to record a telemetry event in the recon layer."""
        self._recorder.record(
            layer=Layer.RECON,
            event_type="api_call",
            action=action,
            source_arn="",
            target_arn=target_arn,
            status=status,
            detection_cost=detection_cost,
            error=error,
            details=details,
        )
