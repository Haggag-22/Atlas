"""Telemetry recorder: in-memory and optional file output."""

import json
from pathlib import Path
from typing import Any

from atlas.telemetry.schema import TelemetryEvent

_recorder: "TelemetryRecorder | None" = None


def get_recorder() -> "TelemetryRecorder":
    global _recorder
    if _recorder is None:
        _recorder = TelemetryRecorder()
    return _recorder


def set_recorder(recorder: "TelemetryRecorder") -> None:
    global _recorder
    _recorder = recorder


class TelemetryRecorder:
    """Records every action in a consistent schema."""

    def __init__(self, output_path: Path | None = None) -> None:
        self._events: list[TelemetryEvent] = []
        self._output_path = output_path
        self._enabled = True

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def set_output_path(self, path: Path | None) -> None:
        self._output_path = path

    def record(
        self,
        actor: str,
        aws_api: str,
        *,
        service: str = "",
        resource_arn: str | None = None,
        region: str | None = None,
        result: str = "success",
        error: str | None = None,
        evidence_pointers: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if not self._enabled:
            return
        event = TelemetryEvent(
            actor=actor,
            aws_api=aws_api,
            service=service,
            resource_arn=resource_arn,
            region=region,
            result=result,
            error=error,
            evidence_pointers=evidence_pointers or [],
            extra=extra or {},
        )
        self._events.append(event)

    def get_events(self) -> list[TelemetryEvent]:
        return list(self._events)

    def get_timeline_dict(self) -> list[dict[str, Any]]:
        return [e.model_dump() for e in self._events]

    def flush_to_file(self) -> None:
        """Write events to output_path if set."""
        if not self._output_path:
            return
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._output_path, "w") as f:
            json.dump(self.get_timeline_dict(), f, indent=2)

    def clear(self) -> None:
        self._events.clear()
