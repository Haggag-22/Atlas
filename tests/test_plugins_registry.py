"""Tests for plugin registry."""

import pytest

from atlas.plugins.registry import get_plugin, list_plugins, register_plugin
from atlas.plugins.techniques.identity_discovery import IdentityDiscoveryPlugin


def test_register_and_get_plugin() -> None:
    plugin = IdentityDiscoveryPlugin()
    register_plugin(plugin)
    assert get_plugin("identity_discovery") is plugin
    assert get_plugin("nonexistent") is None


def test_list_plugins_after_register_builtin() -> None:
    plugins = list_plugins()
    assert "identity_discovery" in plugins
    assert "s3_enumeration" in plugins
    assert "role_trust_analysis" in plugins
