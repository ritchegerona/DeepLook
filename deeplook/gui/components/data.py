"""Dataclass to DataFrame converters for DeepLook GUI."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import pandas as pd


def entities_to_df(entities: list[Any]) -> pd.DataFrame:
    """Convert a list of Entity objects to a pandas DataFrame."""
    if not entities:
        return pd.DataFrame()

    rows = []
    for e in entities:
        row = {
            "type": e.type.value if hasattr(e.type, "value") else str(e.type),
            "value": e.value,
            "confidence": e.confidence,
            "tags": ", ".join(e.tags) if e.tags else "",
            "first_seen": e.first_seen.isoformat() if hasattr(e.first_seen, "isoformat") else str(e.first_seen),
            "last_seen": e.last_seen.isoformat() if hasattr(e.last_seen, "isoformat") else str(e.last_seen),
            "provenance": "; ".join(p.source for p in e.provenance) if e.provenance else "",
        }
        rows.append(row)

    return pd.DataFrame(rows)


def edges_to_df(edges: list[Any], entities: list[Any] | None = None) -> pd.DataFrame:
    """Convert a list of Edge objects to a pandas DataFrame."""
    if not edges:
        return pd.DataFrame()

    entity_map = {}
    if entities:
        entity_map = {e.id: e.value for e in entities}

    rows = []
    for ed in edges:
        source_val = entity_map.get(ed.source_id, ed.source_id[:8])
        target_val = entity_map.get(ed.target_id, ed.target_id[:8])
        row = {
            "source": source_val,
            "target": target_val,
            "relationship": ed.relationship.value if hasattr(ed.relationship, "value") else str(ed.relationship),
            "confidence": ed.confidence,
            "plugin": ed.source_plugin,
            "first_seen": ed.first_seen.isoformat() if hasattr(ed.first_seen, "isoformat") else str(ed.first_seen),
        }
        rows.append(row)

    return pd.DataFrame(rows)


def findings_to_df(findings: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert security findings to a pandas DataFrame."""
    if not findings:
        return pd.DataFrame()

    rows = []
    for f in findings:
        row = {
            "category": f.get("category", ""),
            "check": f.get("check", ""),
            "status": f.get("status", ""),
            "risk": f.get("risk", ""),
            "message": f.get("message", ""),
            "recommendation": f.get("recommendation", ""),
        }
        rows.append(row)

    return pd.DataFrame(rows)


def security_report_to_df(report: Any) -> pd.DataFrame:
    """Convert a SecurityReport to a DataFrame of category scores."""
    if not report:
        return pd.DataFrame()

    rows = []
    for cat in report.categories:
        rows.append(
            {
                "category": cat.name,
                "score": cat.score,
                "weight": f"{cat.weight:.0%}",
                "findings_count": len(cat.findings),
            }
        )

    return pd.DataFrame(rows)


def timeline_to_df(events: list[Any]) -> pd.DataFrame:
    """Convert timeline events to a DataFrame."""
    if not events:
        return pd.DataFrame()

    rows = []
    for ev in events:
        row = {
            "timestamp": ev.get("timestamp", "") if isinstance(ev, dict) else getattr(ev, "timestamp", ""),
            "event_type": ev.get("event_type", "") if isinstance(ev, dict) else getattr(ev, "event_type", ""),
            "target": ev.get("target", "") if isinstance(ev, dict) else getattr(ev, "target", ""),
            "description": ev.get("description", "") if isinstance(ev, dict) else getattr(ev, "description", ""),
        }
        rows.append(row)

    return pd.DataFrame(rows)


def notes_to_df(notes: list[Any]) -> pd.DataFrame:
    """Convert notes to a DataFrame."""
    if not notes:
        return pd.DataFrame()

    rows = []
    for n in notes:
        row = {
            "created_at": n.get("created_at", "") if isinstance(n, dict) else getattr(n, "created_at", ""),
            "content": n.get("content", "") if isinstance(n, dict) else getattr(n, "content", ""),
            "entity_id": n.get("entity_id", "") if isinstance(n, dict) else getattr(n, "entity_id", ""),
        }
        rows.append(row)

    return pd.DataFrame(rows)
