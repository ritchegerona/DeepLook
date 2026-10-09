"""Watchlist monitoring: re-run plugins against watched indicators and
report newly discovered (or vanished) related entities since the last check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from deeplook.core.cache import ResultCache
from deeplook.core.entity import create_entity, refang
from deeplook.core.plugin_loader import get_plugins_for_entity, load_all_plugins
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin


@dataclass
class WatchItem:
    id: int
    type: str
    value: str
    tags: list[str] = field(default_factory=list)
    note: str = ""
    created_at: str = ""
    last_checked: str | None = None
    last_result: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatchItem:
        return cls(
            id=data["id"],
            type=data["type"],
            value=data["value"],
            tags=data.get("tags", []),
            note=data.get("note", ""),
            created_at=data.get("created_at", ""),
            last_checked=data.get("last_checked"),
            last_result=data.get("last_result", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "tags": self.tags,
            "note": self.note,
            "created_at": self.created_at,
            "last_checked": self.last_checked,
            "last_result": self.last_result,
        }


@dataclass
class WatchChange:
    watch_id: int
    value: str
    change: str
    kind: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "watch_id": self.watch_id,
            "value": self.value,
            "change": self.change,
            "kind": self.kind,
            "detail": self.detail,
        }


@dataclass
class WatchCheckResult:
    item: WatchItem
    checked_at: str = ""
    changes: list[WatchChange] = field(default_factory=list)
    error: str | None = None

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item": self.item.to_dict(),
            "checked_at": self.checked_at,
            "changes": [c.to_dict() for c in self.changes],
            "error": self.error,
        }


class WatchlistEngine:
    """Checks watched indicators for new intelligence since the last run."""

    def __init__(
        self,
        workspace: Workspace,
        plugins: dict[str, OSINTPlugin] | None = None,
        cache: ResultCache | None = None,
    ) -> None:
        self.workspace = workspace
        self.plugins = plugins if plugins is not None else load_all_plugins()
        self.cache = cache

    def check(self, item: WatchItem | dict[str, Any]) -> WatchCheckResult:
        watch = item if isinstance(item, WatchItem) else WatchItem.from_dict(item)
        checked_at = datetime.now(UTC).isoformat()
        result = WatchCheckResult(item=watch, checked_at=checked_at)

        try:
            root = create_entity(refang(watch.value))
        except ValueError as exc:
            result.error = str(exc)
            return result

        self.workspace.add_entity(root)

        current: dict[str, str] = {}
        for plugin in get_plugins_for_entity(root.type.value, self.plugins):
            if not plugin.check_key():
                continue
            try:
                plugin_result = plugin.execute(root, self.workspace, self.cache)
            except Exception as exc:  # noqa: BLE001 - a single failing plugin must not abort the check
                result.error = f"{plugin.name}: {exc}"
                continue
            for entity in plugin_result.entities:
                key = entity.value.lower()
                if key == root.value.lower():
                    continue
                current[key] = entity.type.value
                self.workspace.add_entity(entity)
            for edge in plugin_result.edges:
                self.workspace.add_edge(edge)

        previous = {str(e.get("value", "")).lower() for e in watch.last_result.get("entities", [])}

        for key, entity_type in sorted(current.items()):
            if key not in previous:
                result.changes.append(WatchChange(watch.id, root.value, "added", "entity", f"{entity_type}:{key}"))
        for key in sorted(previous - set(current)):
            result.changes.append(WatchChange(watch.id, root.value, "removed", "entity", key))

        snapshot = {
            "checked_at": checked_at,
            "entities": [{"type": t, "value": v} for v, t in sorted(current.items())],
        }
        self.workspace.update_watch_check(watch.id, snapshot)
        watch.last_checked = checked_at
        watch.last_result = snapshot

        if result.changes:
            self.workspace.add_timeline_event(
                "Watchlist change detected",
                target=root.value,
                details={"changes": [c.to_dict() for c in result.changes]},
            )
        else:
            self.workspace.add_timeline_event("Watchlist check", target=root.value, details={"changes": 0})

        return result

    def check_all(self) -> list[WatchCheckResult]:
        return [self.check(item) for item in self.workspace.list_watch()]
