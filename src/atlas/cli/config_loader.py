"""Load AtlasConfig from file and environment."""

from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

from atlas.core.config import AtlasConfig, SafetyConfig, TelemetryConfig, ReconConfig


def load_config_file(path: Path | None = None) -> dict[str, Any]:
    """Load YAML config from path or default locations."""
    default_paths = [
        Path("atlas.yaml"),
        Path("atlas.yml"),
        Path(".atlas.yaml"),
        Path.home() / ".config" / "atlas" / "config.yaml",
    ]
    if path and path.exists():
        raw = path.read_text()
        return yaml.safe_load(raw) or {}
    for p in default_paths:
        if p.exists():
            raw = p.read_text()
            return yaml.safe_load(raw) or {}
    return {}


class EnvSettings(BaseSettings):
    """Environment-override settings for Atlas."""

    model_config = SettingsConfigDict(env_prefix="ATLAS_", extra="ignore")
    aws_profile: str | None = None
    aws_region: str = "us-east-1"
    dry_run: bool | None = None
    allowed_account_ids: str | None = None  # comma-separated
    allowed_regions: str | None = None  # comma-separated


def build_config(config_path: Path | None = None) -> AtlasConfig:
    """Build AtlasConfig from file + env."""
    file_data = load_config_file(config_path)
    env = EnvSettings()
    safety = SafetyConfig(
        **(file_data.get("safety") or {}),
        **(_env_safety_overrides(env)),
    )
    telemetry = TelemetryConfig(**(file_data.get("telemetry") or {}))
    recon = ReconConfig(**(file_data.get("recon") or {}))
    return AtlasConfig(
        safety=safety,
        telemetry=telemetry,
        recon=recon,
        aws_profile=env.aws_profile or file_data.get("aws_profile"),
        aws_region=env.aws_region or file_data.get("aws_region", "us-east-1"),
    )


def _env_safety_overrides(env: EnvSettings) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if env.dry_run is not None:
        overrides["dry_run"] = env.dry_run
    if env.allowed_account_ids:
        overrides["allowed_account_ids"] = [x.strip() for x in env.allowed_account_ids.split(",") if x.strip()]
    if env.allowed_regions:
        overrides["allowed_regions"] = [x.strip() for x in env.allowed_regions.split(",") if x.strip()]
    return overrides
