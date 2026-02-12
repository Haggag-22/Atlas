"""Tests for campaign orchestrator."""

from pathlib import Path

import pytest

from atlas.core.config import AtlasConfig, SafetyConfig
from atlas.core.orchestrator import CampaignOrchestrator


def test_load_campaign(sample_campaign_path: Path, atlas_config: AtlasConfig) -> None:
    orch = CampaignOrchestrator(atlas_config)
    campaign = orch.load_campaign(sample_campaign_path)
    assert campaign.id == "discovery-001"
    assert campaign.name == "AWS Lab Discovery"
    assert len(campaign.steps) >= 1
    assert campaign.steps[0].technique_id == "identity_discovery"


def test_run_dry_run(sample_campaign_path: Path, atlas_config: AtlasConfig) -> None:
    atlas_config.safety.dry_run = True
    orch = CampaignOrchestrator(atlas_config)
    summary = orch.run(sample_campaign_path, dry_run=True)
    assert "run_id" in summary
    assert summary["campaign_id"] == "discovery-001"
    assert len(summary["steps"]) == len(orch.load_campaign(sample_campaign_path).steps)
    for step in summary["steps"]:
        assert step.get("skipped") is True or "technique_id" in step
