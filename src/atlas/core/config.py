"""
atlas.core.config
~~~~~~~~~~~~~~~~~
Typed configuration system for Atlas.

Every tunable parameter lives here.  The CLI and tests construct an
``AtlasConfig`` and pass it down -- no global state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AWSConfig(BaseModel):
    """AWS connection settings."""

    profile: str | None = None
    region: str = "us-east-1"
    access_key_id: str | None = Field(None, exclude=True)   # never serialize
    secret_access_key: str | None = Field(None, exclude=True)
    session_token: str | None = Field(None, exclude=True)
    user_agent_extra: str | None = Field(
        None,
        description=(
            "Custom User-Agent suffix for API requests. Default: 'Atlas/<version>'. "
            "Set to empty string '' to avoid Atlas identification (stealth mode). "
            "GuardDuty can detect pentest distros (Kali, ParrotOS) and tool signatures; "
            "see https://hackingthe.cloud/aws/avoiding-detection/guardduty-pentest/"
        ),
    )


class SafetyConfig(BaseModel):
    """Hard guardrails.  These CANNOT be loosened at runtime."""

    allowed_account_ids: list[str] = Field(
        default_factory=list,
        description="Account IDs the tool is authorized to operate in.  "
                    "Empty list is NOT a wildcard -- it blocks everything.",
    )
    allowed_regions: list[str] = Field(
        default_factory=lambda: ["us-east-1"],
        description="Regions the tool may make API calls to.",
    )
    dry_run: bool = False
    require_confirmation: bool = True
    max_noise_budget: float = Field(
        default=10.0,
        description="Cumulative detection cost ceiling.  Operation aborts if exceeded.",
    )
    rate_limit_per_second: float = 2.0
    jitter_seconds: float = 1.0
    enable_rollback: bool = True

    @field_validator("allowed_account_ids", "allowed_regions", mode="before")
    @classmethod
    def _coerce_list(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return list(v)


class StealthConfig(BaseModel):
    """Stealth execution parameters."""

    noise_budget: float = Field(
        default=10.0,
        description="Total detection cost the operation is willing to spend.",
    )
    min_action_delay_seconds: float = 2.0
    max_action_delay_seconds: float = 30.0
    jitter_factor: float = 0.5             # 0-1, randomness in timing
    avoid_burst: bool = True
    max_api_calls_per_minute: int = 20
    prefer_read_only: bool = True          # prefer recon over writes early on
    business_hours_only: bool = False


class ReconConfig(BaseModel):
    """Which collectors to run and how."""

    enabled_collectors: list[str] = Field(
        default_factory=lambda: [
            "identity",
            "policy",
            "trust",
            "guardrail",
            "logging_config",
            "resource",
            "backup",
            "permission_resolver",
        ],
    )
    resource_types: list[str] = Field(
        default_factory=lambda: [
            "s3", "ec2", "lambda", "rds", "kms",
            "secretsmanager", "ssm", "cloudformation", "ebs", "ecs",
            "ecr", "cognito", "cloudfront",
            "codebuild", "elasticbeanstalk", "bedrock",
        ],
        description="Which resource types the resource collector should enumerate.",
    )
    max_items_per_collector: int = 500
    known_permissions: list[str] = Field(
        default_factory=list,
        description=(
            "Operator-provided permission hints (e.g. 'ec2:*', 's3:GetObject'). "
            "Used when policy documents are unavailable. "
            "Format: list of IAM action strings with optional wildcards."
        ),
    )
    enable_sentinel_probes: bool = Field(
        default=True,
        description=(
            "Enable sentinel API probing as a fallback when policy documents "
            "are unavailable. Adds ~10-15 read-only API calls."
        ),
    )
    bruteforce_concurrency: int = Field(
        default=25,
        description=(
            "Maximum concurrent API calls during brute-force permission "
            "enumeration. Higher values speed up discovery but increase "
            "network load and CloudTrail noise."
        ),
    )


class PlannerConfig(BaseModel):
    """Planner behavior tuning."""

    strategy_preference: str = "auto"      # or specific Strategy value
    path_algorithm: str = "lowest_detection"  # "shortest" | "lowest_detection" | "most_reliable"
    max_path_depth: int = 6
    min_success_probability: float = 0.3
    enable_guardrail_analysis: bool = True
    enable_hypothesis_testing: bool = True


class TelemetryConfig(BaseModel):
    """Structured logging / replay settings."""

    enabled: bool = True
    output_dir: Path = Field(default_factory=lambda: Path("output"))
    log_level: str = "INFO"
    include_raw_responses: bool = False
    enable_replay: bool = True


class OperationConfig(BaseModel):
    """Top-level operation parameters."""

    name: str = "default"
    objective: str = ""
    mode: str = "full"   # "full" | "simulate" | "recon_only" | "plan_only" | "replay"
    target_privilege: str = ""  # e.g. "admin", specific ARN, etc.


class AtlasConfig(BaseModel):
    """Root configuration -- assembled from YAML / CLI flags / env vars."""

    operation: OperationConfig = Field(default_factory=OperationConfig)
    aws: AWSConfig = Field(default_factory=AWSConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    planner: PlannerConfig = Field(default_factory=PlannerConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
