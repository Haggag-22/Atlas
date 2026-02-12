"""Pydantic configuration and campaign/technique models."""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SafetyConfig(BaseModel):
    """Safety controls: allowlists and behavior."""

    allowed_account_ids: list[str] = Field(
        default_factory=list,
        description="Hard allowlist of AWS account IDs; empty = no restriction (unsafe).",
    )
    allowed_regions: list[str] = Field(
        default_factory=lambda: [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
        ],
        description="Hard allowlist of regions.",
    )
    require_confirmation_destructive: bool = True
    dry_run: bool = False
    rate_limit_per_second: float = 5.0
    jitter_seconds: float = 0.5
    lab_only_banner: bool = True


class TelemetryConfig(BaseModel):
    """Telemetry recording options."""

    enabled: bool = True
    output_path: Path | None = None
    enrich_cloudtrail: bool = False
    cloudtrail_log_path: Path | None = None


class ReconConfig(BaseModel):
    """Recon scanner options."""

    scan_paths: list[Path] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(
        default_factory=lambda: ["*.pyc", ".git/*", "node_modules/*", "__pycache__/*"]
    )
    max_file_size_bytes: int = 1_000_000  # 1MB


class AtlasConfig(BaseModel):
    """Root configuration for Atlas."""

    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    aws_profile: str | None = None
    aws_region: str = "us-east-1"

    @field_validator("allowed_account_ids", "allowed_regions", mode="before")
    @classmethod
    def coerce_list(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return list(v)


class TechniqueStepConfig(BaseModel):
    """Single step in a campaign: technique ID + parameters."""

    technique_id: str = Field(..., description="Plugin ID e.g. identity_discovery")
    name: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    skip_if: str | None = Field(
        None,
        description="Optional condition (e.g. state key) to skip this step.",
    )


class CampaignDefinition(BaseModel):
    """Campaign YAML structure."""

    id: str = Field(..., description="Unique campaign ID")
    name: str = Field(..., description="Human-readable name")
    description: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    steps: list[TechniqueStepConfig] = Field(default_factory=list)

    @field_validator("steps")
    @classmethod
    def steps_non_empty(cls, v: list[TechniqueStepConfig]) -> list[TechniqueStepConfig]:
        if not v:
            raise ValueError("Campaign must have at least one step")
        return v
