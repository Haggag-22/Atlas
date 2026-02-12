"""Telemetry event schema: timestamp, actor, API, resource ARN, region, result, error."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TelemetryEvent(BaseModel):
    """Single recorded action."""

    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    actor: str = Field(..., description="Technique ID or 'recon' or 'cli'")
    aws_api: str = Field(..., description="e.g. iam:ListUsers")
    service: str = Field("", description="e.g. iam, s3")
    resource_arn: str | None = None
    region: str | None = None
    result: str = Field("success", description="success | failure | skipped")
    error: str | None = None
    evidence_pointers: list[str] = Field(
        default_factory=list,
        description="Paths or IDs to evidence (e.g. log file, event ID).",
    )
    extra: dict[str, Any] = Field(default_factory=dict)
