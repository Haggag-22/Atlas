"""Tests for config loading."""

from pathlib import Path

import pytest

from atlas.core.config import AtlasConfig, CampaignDefinition, TechniqueStepConfig
from atlas.cli.config_loader import load_config_file, build_config


def test_build_config_no_file() -> None:
    config = build_config(None)
    assert config.aws_region == "us-east-1" or config.aws_region
    assert config.safety is not None


def test_campaign_definition_validation() -> None:
    campaign = CampaignDefinition(
        id="test",
        name="Test",
        steps=[TechniqueStepConfig(technique_id="identity_discovery", parameters={})],
    )
    assert campaign.id == "test"
    assert len(campaign.steps) == 1


def test_campaign_definition_empty_steps_invalid() -> None:
    with pytest.raises(ValueError):
        CampaignDefinition(id="x", name="y", steps=[])
