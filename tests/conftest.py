"""Pytest fixtures."""

from pathlib import Path

import pytest

from atlas.core.config import AtlasConfig, SafetyConfig
from atlas.core.state import CampaignState
from atlas.plugins.registry import clear_registry
from atlas.plugins.techniques import register_builtin_plugins


@pytest.fixture
def safety_config() -> SafetyConfig:
    return SafetyConfig(
        allowed_account_ids=["123456789012"],
        allowed_regions=["us-east-1", "eu-west-1"],
        dry_run=True,
    )


@pytest.fixture
def atlas_config(safety_config: SafetyConfig) -> AtlasConfig:
    return AtlasConfig(safety=safety_config, aws_region="us-east-1")


@pytest.fixture
def campaign_state() -> CampaignState:
    return CampaignState(campaign_id="test", run_id="run-1")


@pytest.fixture(autouse=True)
def reset_plugins() -> None:
    clear_registry()
    register_builtin_plugins()
    yield
    clear_registry()


@pytest.fixture
def sample_campaign_path() -> Path:
    return Path(__file__).parent.parent / "campaigns" / "discovery.yaml"
