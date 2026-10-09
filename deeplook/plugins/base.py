"""Plugin base class and registration decorator."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from deeplook.core.cache import ResultCache
from deeplook.core.edge import Edge
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace


class PluginResult:
    """Standardized result from a plugin execution."""

    def __init__(self) -> None:
        self.entities: list[Entity] = []
        self.edges: list[Edge] = []
        self.metadata: dict[str, Any] = {}
        self.warnings: list[str] = []
        self.raw_data: dict[str, Any] = {}

    def add_entity(self, entity: Entity) -> None:
        self.entities.append(entity)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)


class OSINTPlugin(ABC):
    """Base class for all OSINT plugins."""

    name: str = "base"
    description: str = ""
    entity_types: list[EntityType] = []
    requires_key: bool = False
    key_env_var: str = ""
    confidence: float = 0.8
    version: str = "1.0.0"
    min_deeplook_version: str = "1.0.0"
    tags: list[str] = []

    def __init__(self) -> None:
        self._start_time: float = 0
        self._duration_ms: int = 0

    @abstractmethod
    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        """Execute the plugin against a target entity."""
        ...

    def check_key(self) -> bool:
        """Check if required API key is available. Override for custom logic."""
        if not self.requires_key:
            return True
        import os

        return bool(os.environ.get(self.key_env_var))

    def execute(self, entity: Entity, workspace: Workspace, cache: ResultCache | None = None) -> PluginResult:
        """Wrapper around run() with timing, caching, and error handling."""
        if cache and not self.requires_key:
            cached = cache.get(self.name, entity.value)
            if cached:
                result = PluginResult()
                result.metadata["from_cache"] = True
                return result

        self._start_time = time.time()
        try:
            result = self.run(entity, workspace)
            self._duration_ms = int((time.time() - self._start_time) * 1000)
            result.metadata["plugin"] = self.name
            result.metadata["duration_ms"] = self._duration_ms
            result.metadata["from_cache"] = False

            if cache and not self.requires_key:
                cache.set(
                    self.name,
                    entity.value,
                    {
                        "entities": len(result.entities),
                        "edges": len(result.edges),
                        "metadata": result.metadata,
                    },
                )

            return result
        except Exception as e:
            self._duration_ms = int((time.time() - self._start_time) * 1000)
            result = PluginResult()
            result.add_warning(f"Plugin {self.name} failed: {e}")
            result.metadata["error"] = str(e)
            result.metadata["duration_ms"] = self._duration_ms
            return result

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "entity_types": [t.value for t in self.entity_types],
            "requires_key": self.requires_key,
            "key_env_var": self.key_env_var,
            "confidence": self.confidence,
            "version": self.version,
            "tags": self.tags,
        }


# --- Plugin Registry ---

_REGISTRY: dict[str, type[OSINTPlugin]] = {}


def register_plugin(cls: type[OSINTPlugin]) -> type[OSINTPlugin]:
    """Decorator to register a plugin class."""
    instance = cls()
    _REGISTRY[instance.name] = cls
    return cls


def get_registry() -> dict[str, type[OSINTPlugin]]:
    return dict(_REGISTRY)


def get_plugin(name: str) -> OSINTPlugin | None:
    cls = _REGISTRY.get(name)
    return cls() if cls else None
