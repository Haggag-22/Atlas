"""Plugin registry: register and resolve technique plugins by ID."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from atlas.core.plugin import TechniquePlugin

_registry: dict[str, "TechniquePlugin"] = {}


def register_plugin(plugin: "TechniquePlugin") -> None:
    _registry[plugin.id] = plugin


def get_plugin(technique_id: str) -> "TechniquePlugin | None":
    return _registry.get(technique_id)


def list_plugins() -> dict[str, "TechniquePlugin"]:
    return dict(_registry)


def clear_registry() -> None:
    _registry.clear()
