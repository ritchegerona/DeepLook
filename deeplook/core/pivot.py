"""Recursive entity expansion ("pivoting") engine for DeepLook.

Given a seed indicator, :class:`PivotEngine` repeatedly runs the OSINT plugins
that apply to each newly discovered entity, breadth-first, until the configured
depth or entity budget is reached. Discovered entities and their relationships
are de-duplicated by ``(type, value)`` and persisted to the workspace so the
resulting graph stays clean and connected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deeplook.core.cache import ResultCache
from deeplook.core.edge import Edge
from deeplook.core.entity import Entity, EntityType, create_entity
from deeplook.core.plugin_loader import get_plugins_for_entity, load_all_plugins
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin


def _key(entity: Entity) -> tuple[str, str]:
    return (entity.type.value, entity.value.lower())


@dataclass
class PivotNode:
    """A single entity discovered during a pivot."""

    value: str
    type: str
    depth: int
    plugin: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "type": self.type, "depth": self.depth, "plugin": self.plugin}


@dataclass
class PivotResult:
    """Outcome of a pivot run."""

    root: str
    max_depth: int
    nodes: list[PivotNode] = field(default_factory=list)
    entities_added: int = 0
    edges_added: int = 0
    plugins_run: int = 0
    truncated: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def discovered(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "max_depth": self.max_depth,
            "entities_added": self.entities_added,
            "edges_added": self.edges_added,
            "plugins_run": self.plugins_run,
            "truncated": self.truncated,
            "errors": self.errors,
            "nodes": [n.to_dict() for n in self.nodes],
        }


class PivotEngine:
    """Breadth-first entity expansion using the plugin registry."""

    def __init__(
        self,
        workspace: Workspace,
        max_depth: int = 2,
        max_entities: int = 50,
        plugins: dict[str, OSINTPlugin] | None = None,
        cache: ResultCache | None = None,
        plugin_filter: list[str] | None = None,
    ) -> None:
        self.workspace = workspace
        self.max_depth = max(0, max_depth)
        self.max_entities = max(1, max_entities)
        self.plugins = plugins if plugins is not None else load_all_plugins()
        self.cache = cache
        self.plugin_filter = set(plugin_filter) if plugin_filter else None
        self._canonical: dict[tuple[str, str], Entity] = {}
        self._expanded: set[tuple[str, str]] = set()

    def _plugins_for(self, entity: Entity) -> list[OSINTPlugin]:
        candidates = get_plugins_for_entity(entity.type.value, self.plugins)
        if self.plugin_filter is not None:
            candidates = [p for p in candidates if p.name in self.plugin_filter]
        return candidates

    def _register(self, entity: Entity) -> Entity:
        """Return the canonical entity for a value, adopting/creating as needed."""
        key = _key(entity)
        existing = self._canonical.get(key)
        if existing is not None:
            return existing

        adopted = self.workspace.find_entity_by_value(entity.value)
        if adopted is not None and adopted.type == entity.type:
            entity = adopted
        else:
            self.workspace.add_entity(entity)

        self._canonical[key] = entity
        return entity

    def pivot(self, target: str, entity_type: EntityType | None = None) -> PivotResult:
        """Expand ``target`` breadth-first up to the configured limits."""
        root = self._register(create_entity(target, entity_type))

        result = PivotResult(root=root.value, max_depth=self.max_depth)
        result.nodes.append(PivotNode(root.value, root.type.value, depth=0))
        self._expanded.add(_key(root))

        frontier: list[tuple[Entity, int]] = [(root, 0)]

        while frontier:
            entity, depth = frontier.pop(0)
            if depth >= self.max_depth:
                continue
            if len(self._canonical) >= self.max_entities:
                result.truncated = True
                break

            for plugin in self._plugins_for(entity):
                if not plugin.check_key():
                    continue

                plugin_result = plugin.execute(entity, self.workspace, self.cache)
                result.plugins_run += 1
                result.errors.extend(plugin_result.warnings)

                id_map: dict[str, Entity] = {}
                for found in plugin_result.entities:
                    key = _key(found)
                    if key not in self._canonical and len(self._canonical) >= self.max_entities:
                        result.truncated = True
                        continue
                    canonical = self._register(found)
                    id_map[found.id] = canonical
                    if key not in self._expanded:
                        self._expanded.add(key)
                        frontier.append((canonical, depth + 1))
                        result.nodes.append(PivotNode(canonical.value, canonical.type.value, depth + 1, plugin.name))

                valid_ids = {e.id for e in self._canonical.values()}
                for edge in plugin_result.edges:
                    src = id_map.get(edge.source_id)
                    tgt = id_map.get(edge.target_id)
                    src_id = src.id if src else edge.source_id
                    tgt_id = tgt.id if tgt else edge.target_id
                    if src_id == tgt_id:
                        continue
                    if src_id not in valid_ids or tgt_id not in valid_ids:
                        continue
                    self.workspace.add_edge(
                        Edge(
                            source_id=src_id,
                            target_id=tgt_id,
                            relationship=edge.relationship,
                            confidence=edge.confidence,
                            source_plugin=edge.source_plugin or plugin.name,
                            metadata=edge.metadata,
                        )
                    )
                    result.edges_added += 1

        result.entities_added = max(0, len(self._canonical) - 1)
        self.workspace.add_timeline_event(
            "Pivot completed",
            target=root.value,
            details={
                "depth": self.max_depth,
                "entities": result.entities_added,
                "edges": result.edges_added,
            },
        )
        return result
