"""Source tracking and provenance management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class ProvenanceTracker:
    """Track where each finding came from across an investigation."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def record(
        self,
        source: str,
        target: str,
        entity_type: str,
        entity_value: str,
        confidence: float = 1.0,
        raw_data: dict[str, Any] | None = None,
    ) -> None:
        self._entries.append(
            {
                "source": source,
                "target": target,
                "entity_type": entity_type,
                "entity_value": entity_value,
                "confidence": confidence,
                "timestamp": datetime.now(UTC).isoformat(),
                "raw_data": raw_data,
            }
        )

    def for_entity(self, entity_value: str) -> list[dict[str, Any]]:
        return [e for e in self._entries if e["entity_value"] == entity_value]

    def for_source(self, source: str) -> list[dict[str, Any]]:
        return [e for e in self._entries if e["source"] == source]

    def for_target(self, target: str) -> list[dict[str, Any]]:
        return [e for e in self._entries if e["target"] == target]

    def all_entries(self) -> list[dict[str, Any]]:
        return list(self._entries)

    def summary(self) -> dict[str, Any]:
        sources: dict[str, int] = {}
        entity_types: dict[str, int] = {}
        for entry in self._entries:
            sources[entry["source"]] = sources.get(entry["source"], 0) + 1
            entity_types[entry["entity_type"]] = entity_types.get(entry["entity_type"], 0) + 1
        return {
            "total_findings": len(self._entries),
            "sources": sources,
            "entity_types": entity_types,
        }
