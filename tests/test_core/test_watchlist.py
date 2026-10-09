"""Tests for watchlist management and change detection."""

from __future__ import annotations

from deeplook.core.entity import Entity, EntityType, create_entity
from deeplook.core.watchlist import WatchItem, WatchlistEngine
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult


class FakePlugin(OSINTPlugin):
    name = "fake"
    entity_types = [EntityType.DOMAIN]

    def __init__(self, values: list[str] | None = None) -> None:
        super().__init__()
        self.values = values or []
        self.calls = 0

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        self.calls += 1
        result = PluginResult()
        for value in self.values:
            result.add_entity(create_entity(value))
        return result


def _ws(tmp_path, name="watch"):
    return Workspace(name, base_dir=tmp_path)


def test_add_list_and_dedupe(tmp_path):
    ws = _ws(tmp_path)
    first = ws.add_watch("domain", "evil.com", tags=["apt"], note="watch me")
    second = ws.add_watch("domain", "evil.com")

    assert first == second
    items = ws.list_watch()
    assert len(items) == 1
    assert items[0]["tags"] == ["apt"]
    assert items[0]["note"] == "watch me"


def test_remove_watch(tmp_path):
    ws = _ws(tmp_path)
    watch_id = ws.add_watch("domain", "evil.com")
    assert ws.remove_watch(watch_id) is True
    assert ws.remove_watch(watch_id) is False
    assert ws.list_watch() == []


def test_watch_item_roundtrip():
    data = {
        "id": 3,
        "type": "domain",
        "value": "evil.com",
        "tags": ["x"],
        "note": "n",
        "created_at": "2026-01-01T00:00:00+00:00",
        "last_checked": None,
        "last_result": {"entities": []},
    }
    item = WatchItem.from_dict(data)
    assert item.value == "evil.com"
    assert item.to_dict()["id"] == 3


def test_check_detects_new_entities(tmp_path):
    ws = _ws(tmp_path)
    watch_id = ws.add_watch("domain", "evil.com")
    plugin = FakePlugin(["a.evil.com"])
    engine = WatchlistEngine(ws, plugins={"fake": plugin})

    first = engine.check(ws.get_watch(watch_id))
    assert len(first.changes) == 1
    assert first.changes[0].change == "added"
    assert first.changes[0].detail == "domain:a.evil.com"

    plugin.values = ["a.evil.com", "b.evil.com"]
    second = engine.check(ws.get_watch(watch_id))
    assert len(second.changes) == 1
    assert second.changes[0].detail == "domain:b.evil.com"


def test_check_no_changes(tmp_path):
    ws = _ws(tmp_path)
    watch_id = ws.add_watch("domain", "evil.com")
    plugin = FakePlugin(["a.evil.com"])
    engine = WatchlistEngine(ws, plugins={"fake": plugin})

    engine.check(ws.get_watch(watch_id))
    second = engine.check(ws.get_watch(watch_id))

    assert second.changes == []
    assert second.has_changes is False


def test_check_detects_removed_entities(tmp_path):
    ws = _ws(tmp_path)
    watch_id = ws.add_watch("domain", "evil.com")
    plugin = FakePlugin(["a.evil.com", "b.evil.com"])
    engine = WatchlistEngine(ws, plugins={"fake": plugin})

    engine.check(ws.get_watch(watch_id))
    plugin.values = ["a.evil.com"]
    second = engine.check(ws.get_watch(watch_id))

    assert len(second.changes) == 1
    assert second.changes[0].change == "removed"
    assert second.changes[0].detail == "b.evil.com"


def test_check_unrecognized_value_sets_error(tmp_path):
    ws = _ws(tmp_path)
    watch_id = ws.add_watch("domain", "not a real indicator")
    engine = WatchlistEngine(ws, plugins={})

    result = engine.check(ws.get_watch(watch_id))

    assert result.error is not None
    assert result.changes == []
