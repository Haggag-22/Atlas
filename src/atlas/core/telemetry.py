"""
atlas.core.telemetry
~~~~~~~~~~~~~~~~~~~~
Structured event logging with correlation IDs and replay support.

Every action across all three layers produces a ``TelemetryEvent`` that is
written to a JSON-lines file.  The replay reader can reconstruct the full
operation timeline from this file.

Design rules:
  - Events are append-only (never mutated after write).
  - Each event carries a ``correlation_id`` tying it to the operation.
  - The recorder is async-safe and thread-safe.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
import structlog

from atlas.core.types import Layer

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------
class TelemetryEvent:
    """A single recorded event.

    Kept as a plain class (not Pydantic) for speed -- telemetry is hot-path.
    """

    __slots__ = (
        "event_id",
        "correlation_id",
        "timestamp",
        "layer",
        "event_type",
        "action",
        "source_arn",
        "target_arn",
        "status",
        "detection_cost",
        "error",
        "details",
    )

    def __init__(
        self,
        *,
        correlation_id: str,
        layer: Layer,
        event_type: str,
        action: str = "",
        source_arn: str = "",
        target_arn: str = "",
        status: str = "success",
        detection_cost: float = 0.0,
        error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.event_id = uuid.uuid4().hex[:12]
        self.correlation_id = correlation_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.layer = layer.value
        self.event_type = event_type
        self.action = action
        self.source_arn = source_arn
        self.target_arn = target_arn
        self.status = status
        self.detection_cost = detection_cost
        self.error = error
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "layer": self.layer,
            "event_type": self.event_type,
            "action": self.action,
            "source_arn": self.source_arn,
            "target_arn": self.target_arn,
            "status": self.status,
            "detection_cost": self.detection_cost,
            "error": self.error,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Recorder (write path)
# ---------------------------------------------------------------------------
class TelemetryRecorder:
    """Accumulates events and flushes them to a JSONL file.

    Thread-safe via a simple list; async-safe because ``flush`` is awaitable.
    """

    def __init__(self, correlation_id: str | None = None) -> None:
        self._correlation_id = correlation_id or uuid.uuid4().hex[:16]
        self._events: list[TelemetryEvent] = []

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def record(
        self,
        *,
        layer: Layer,
        event_type: str,
        action: str = "",
        source_arn: str = "",
        target_arn: str = "",
        status: str = "success",
        detection_cost: float = 0.0,
        error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> TelemetryEvent:
        event = TelemetryEvent(
            correlation_id=self._correlation_id,
            layer=layer,
            event_type=event_type,
            action=action,
            source_arn=source_arn,
            target_arn=target_arn,
            status=status,
            detection_cost=detection_cost,
            error=error,
            details=details,
        )
        self._events.append(event)
        logger.debug(
            "telemetry_event",
            event_id=event.event_id,
            layer=event.layer,
            event_type=event_type,
            action=action,
            status=status,
        )
        return event

    @property
    def events(self) -> list[TelemetryEvent]:
        return list(self._events)

    @property
    def event_count(self) -> int:
        return len(self._events)

    def get_timeline(self) -> list[dict[str, Any]]:
        """Return all events as dicts, sorted by timestamp."""
        return [e.to_dict() for e in sorted(self._events, key=lambda e: e.timestamp)]

    async def flush_to_file(self, path: Path) -> int:
        """Append all events to a JSONL file.  Returns count written."""
        path.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        async with aiofiles.open(path, mode="a") as f:
            for event in self._events:
                line = json.dumps(event.to_dict(), default=str)
                await f.write(line + "\n")
                count += 1
        logger.info("telemetry_flushed", path=str(path), count=count)
        return count

    def clear(self) -> None:
        self._events.clear()


# ---------------------------------------------------------------------------
# Reader (replay path)
# ---------------------------------------------------------------------------
class TelemetryReader:
    """Reads a JSONL telemetry file for replay or analysis."""

    def __init__(self, path: Path) -> None:
        self._path = path

    async def read_all(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        async with aiofiles.open(self._path, mode="r") as f:
            async for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    async def read_by_layer(self, layer: str) -> list[dict[str, Any]]:
        all_events = await self.read_all()
        return [e for e in all_events if e.get("layer") == layer]

    async def read_by_correlation(self, correlation_id: str) -> list[dict[str, Any]]:
        all_events = await self.read_all()
        return [e for e in all_events if e.get("correlation_id") == correlation_id]

    async def summary(self) -> dict[str, Any]:
        """Quick stats about the telemetry file."""
        events = await self.read_all()
        layers: dict[str, int] = {}
        statuses: dict[str, int] = {}
        total_detection_cost = 0.0
        for e in events:
            layer = e.get("layer", "unknown")
            layers[layer] = layers.get(layer, 0) + 1
            status = e.get("status", "unknown")
            statuses[status] = statuses.get(status, 0) + 1
            total_detection_cost += e.get("detection_cost", 0.0)
        return {
            "total_events": len(events),
            "events_by_layer": layers,
            "events_by_status": statuses,
            "total_detection_cost": round(total_detection_cost, 4),
        }
