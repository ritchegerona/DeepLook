"""Tests for the recursive pivot engine."""

from __future__ import annotations

import pytest

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import EntityType, create_entity
from deeplook.core.pivot import PivotEngine
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult


class StubPlugin(OSINTPlugin):
    """Deterministic plugin that returns configured children for testing."""

    def __init__(
        self,
        name: str,
        entity_types: list[EntityType],
        children: list[tuple[str, EntityType, RelationshipType]] | None = None,
        requires_key: bool = False,
        key_env_var: str = "",
    ) -> None:
        super().__init__()
        self.name = name
        self.entity_types = entity_types
        self.children = children or []
        self.requires_key = requires_key
        self.key_env_var = key_env_var
        self.calls = 0

    def run(self, entity, workspace):
        self.calls += 1
        result = PluginResult()
        for value, etype, rel in self.children:
            child = create_entity(value, etype)
            result.add_entity(child)
            result.add_edge(Edge(source_id=entity.id, target_id=child.id, relationship=rel))
        return result


def _workspace(tmp_path, name: str = "pivot") -> Workspace:
    return Workspace(name, base_dir=tmp_path)


def test_pivot_discovers_linked_entities(tmp_path):
    ip_plugin = StubPlugin(
        "ip-stub",
        [EntityType.IP],
        children=[("evil.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH)],
    )
    domain_plugin = StubPlugin("domain-stub", [EntityType.DOMAIN])
    plugins = {"ip-stub": ip_plugin, "domain-stub": domain_plugin}

    engine = PivotEngine(_workspace(tmp_path), max_depth=1, plugins=plugins)
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 2
    assert result.entities_added == 1
    assert result.edges_added == 1
    assert ip_plugin.calls == 1
    # The discovered domain sits at depth 1, so it is not expanded.
    assert domain_plugin.calls == 0


def test_pivot_expands_to_configured_depth(tmp_path):
    ip_plugin = StubPlugin(
        "ip-stub",
        [EntityType.IP],
        children=[("evil.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH)],
    )
    domain_plugin = StubPlugin(
        "domain-stub",
        [EntityType.DOMAIN],
        children=[("1.2.3.4", EntityType.IP, RelationshipType.RESOLVES_TO)],
    )
    plugins = {"ip-stub": ip_plugin, "domain-stub": domain_plugin}

    engine = PivotEngine(_workspace(tmp_path), max_depth=2, plugins=plugins)
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 3
    assert domain_plugin.calls == 1


def test_pivot_respects_max_entities(tmp_path):
    children = [(f"host{i}.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH) for i in range(5)]
    ip_plugin = StubPlugin("ip-stub", [EntityType.IP], children=children)

    engine = PivotEngine(_workspace(tmp_path), max_depth=1, max_entities=3, plugins={"ip-stub": ip_plugin})
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 3
    assert result.entities_added == 2
    assert result.truncated is True


def test_pivot_is_cycle_safe(tmp_path):
    ip_plugin = StubPlugin(
        "ip-stub",
        [EntityType.IP],
        children=[("evil.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH)],
    )
    domain_plugin = StubPlugin(
        "domain-stub",
        [EntityType.DOMAIN],
        children=[("8.8.8.8", EntityType.IP, RelationshipType.RESOLVES_TO)],
    )
    plugins = {"ip-stub": ip_plugin, "domain-stub": domain_plugin}

    engine = PivotEngine(_workspace(tmp_path), max_depth=5, plugins=plugins)
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 2
    assert ip_plugin.calls == 1
    assert domain_plugin.calls == 1


def test_pivot_deduplicates_shared_values(tmp_path):
    ip_plugin_a = StubPlugin(
        "ip-a",
        [EntityType.IP],
        children=[("shared.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH)],
    )
    ip_plugin_b = StubPlugin(
        "ip-b",
        [EntityType.IP],
        children=[("SHARED.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH)],
    )
    plugins = {"ip-a": ip_plugin_a, "ip-b": ip_plugin_b}

    engine = PivotEngine(_workspace(tmp_path), max_depth=1, plugins=plugins)
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 2
    assert result.entities_added == 1
    assert result.edges_added == 2


def test_pivot_skips_plugins_requiring_missing_key(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPLOOK_TEST_KEY", raising=False)
    ip_plugin = StubPlugin(
        "ip-stub",
        [EntityType.IP],
        children=[("evil.example.com", EntityType.DOMAIN, RelationshipType.ASSOCIATED_WITH)],
        requires_key=True,
        key_env_var="DEEPLOOK_TEST_KEY",
    )

    engine = PivotEngine(_workspace(tmp_path), max_depth=1, plugins={"ip-stub": ip_plugin})
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 1
    assert ip_plugin.calls == 0


def test_pivot_adopts_existing_workspace_entity(tmp_path):
    ws = _workspace(tmp_path)
    existing = create_entity("8.8.8.8", EntityType.IP)
    ws.add_entity(existing)

    ip_plugin = StubPlugin("ip-stub", [EntityType.IP])
    engine = PivotEngine(ws, max_depth=1, plugins={"ip-stub": ip_plugin})
    result = engine.pivot("8.8.8.8")

    assert result.discovered == 1
    assert ws.find_entity_by_value("8.8.8.8").id == existing.id


def test_pivot_rejects_unknown_target(tmp_path):
    engine = PivotEngine(_workspace(tmp_path), max_depth=1, plugins={})
    with pytest.raises(ValueError):
        engine.pivot("this is not an indicator")
