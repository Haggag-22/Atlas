"""Tests for plugin interface."""

from typing import Any

import pytest

from atlas.core.plugin import TechniquePlugin, TechniqueResult
from atlas.core.state import CampaignState


class DummyPlugin(TechniquePlugin):
    @property
    def id(self) -> str:
        return "dummy"

    @property
    def name(self) -> str:
        return "Dummy"

    @property
    def description(self) -> str:
        return "A dummy plugin"

    def execute(
        self,
        state: CampaignState,
        parameters: dict[str, Any],
        config: Any = None,
    ) -> TechniqueResult:
        return TechniqueResult(
            success=True,
            message="ok",
            outputs={"key": "value"},
        )


def test_dummy_plugin_execute() -> None:
    plugin = DummyPlugin()
    state = CampaignState()
    result = plugin.execute(state, {}, None)
    assert result.success is True
    assert result.outputs == {"key": "value"}


def test_plugin_rollback_default() -> None:
    plugin = DummyPlugin()
    state = CampaignState()
    prev = TechniqueResult(success=True, outputs={})
    result = plugin.rollback(state, {}, prev, None)
    assert result.success is True
    assert "not implemented" in result.message.lower()
