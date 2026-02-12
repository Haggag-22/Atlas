"""Tests for campaign state."""

import pytest

from atlas.core.state import (
    CampaignState,
    DiscoveredAccount,
    DiscoveredRole,
    DiscoveredResource,
    Finding,
)


def test_state_initialization() -> None:
    state = CampaignState()
    assert state.campaign_id == ""
    assert state.run_id == ""
    assert state.accounts == []
    assert state.findings == []


def test_get_account_ids() -> None:
    state = CampaignState()
    state.accounts = [
        DiscoveredAccount(account_id="111", source="test"),
        DiscoveredAccount(account_id="222", source="test"),
    ]
    assert state.get_account_ids() == ["111", "222"]


def test_add_finding() -> None:
    state = CampaignState()
    state.add_finding(Finding(finding_type="test", title="T", description="D"))
    assert len(state.findings) == 1
    assert state.findings[0].title == "T"


def test_set_get_step_output() -> None:
    state = CampaignState()
    state.set_step_output("identity_discovery", {"users": ["u1"]})
    assert state.get_step_output("identity_discovery") == {"users": ["u1"]}
    assert state.get_step_output("missing", "default") == "default"
