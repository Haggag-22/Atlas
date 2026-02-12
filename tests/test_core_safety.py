"""Tests for safety controls."""

import pytest

from atlas.core.config import SafetyConfig
from atlas.core.safety import (
    check_account_allowed,
    check_region_allowed,
    get_lab_banner,
)


def test_lab_banner_non_empty() -> None:
    banner = get_lab_banner()
    assert "LAB" in banner
    assert "ATLAS" in banner


def test_check_account_allowed_empty_allowlist() -> None:
    config = SafetyConfig(allowed_account_ids=[])
    assert check_account_allowed("123456789012", config) is True


def test_check_account_allowed_with_allowlist() -> None:
    config = SafetyConfig(allowed_account_ids=["111", "222"])
    assert check_account_allowed("111", config) is True
    assert check_account_allowed("222", config) is True
    assert check_account_allowed("333", config) is False


def test_check_region_allowed() -> None:
    config = SafetyConfig(allowed_regions=["us-east-1", "eu-west-1"])
    assert check_region_allowed("us-east-1", config) is True
    assert check_region_allowed("eu-west-1", config) is True
    assert check_region_allowed("ap-south-1", config) is False
