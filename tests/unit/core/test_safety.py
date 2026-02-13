"""Tests for atlas.core.safety — SafetyGate."""

import pytest

from atlas.core.config import SafetyConfig
from atlas.core.safety import SafetyGate


@pytest.fixture
def gate() -> SafetyGate:
    config = SafetyConfig(
        allowed_account_ids=["123456789012"],
        allowed_regions=["us-east-1"],
        max_noise_budget=5.0,
        dry_run=False,
    )
    return SafetyGate(config)


def test_account_allowed(gate: SafetyGate):
    verdict = gate.check_account("123456789012")
    assert verdict.allowed


def test_account_blocked(gate: SafetyGate):
    verdict = gate.check_account("999999999999")
    assert not verdict.allowed
    assert "not in the allowlist" in verdict.reason


def test_empty_allowlist_blocks():
    config = SafetyConfig(allowed_account_ids=[], allowed_regions=["us-east-1"])
    gate = SafetyGate(config)
    verdict = gate.check_account("123456789012")
    assert not verdict.allowed
    assert "No allowed_account_ids" in verdict.reason


def test_region_allowed(gate: SafetyGate):
    assert gate.check_region("us-east-1").allowed


def test_region_blocked(gate: SafetyGate):
    assert not gate.check_region("eu-west-1").allowed


def test_noise_budget(gate: SafetyGate):
    assert gate.check_noise_budget(3.0).allowed
    gate.spend_noise(3.0)
    # After spending 3.0, spending another 2.5 would total 5.5 > 5.0 budget
    assert not gate.check_noise_budget(2.5).allowed
    # But spending 1.5 is still within budget (3.0 + 1.5 = 4.5 < 5.0)
    assert gate.check_noise_budget(1.5).allowed


def test_noise_budget_warning(gate: SafetyGate):
    gate.spend_noise(4.5)
    verdict = gate.check_noise_budget(0.1)
    assert verdict.allowed
    assert len(verdict.warnings) > 0  # should warn above 80%


def test_full_check(gate: SafetyGate):
    verdict = gate.full_check(
        account_id="123456789012",
        region="us-east-1",
        detection_cost=1.0,
    )
    assert verdict.allowed


def test_full_check_blocked_region(gate: SafetyGate):
    verdict = gate.full_check(
        account_id="123456789012",
        region="ap-southeast-1",
        detection_cost=1.0,
    )
    assert not verdict.allowed


def test_emergency_stop(gate: SafetyGate):
    assert not gate.is_stopped
    gate.trigger_emergency_stop("test")
    assert gate.is_stopped
    verdict = gate.full_check(
        account_id="123456789012",
        region="us-east-1",
    )
    assert not verdict.allowed
    assert "Emergency stop" in verdict.reason


def test_noise_remaining(gate: SafetyGate):
    assert gate.noise_remaining == 5.0
    gate.spend_noise(2.0)
    assert gate.noise_remaining == 3.0
