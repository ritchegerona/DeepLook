"""JSON export for DeepLook workspaces."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deeplook import __version__
from deeplook.core.workspace import Workspace


def export_json(workspace: Workspace, output_path: Path | None = None) -> str:
    entities = workspace.all_entities()
    edges = workspace.all_edges()
    notes = workspace.get_notes()
    timeline = workspace.get_timeline()

    data: dict[str, Any] = {
        "metadata": {
            "tool": "deeplook",
            "version": __version__,
            "exported_at": datetime.now(UTC).isoformat(),
            "workspace": workspace.name,
            "entity_count": len(entities),
            "edge_count": len(edges),
            "note_count": len(notes),
        },
        "entities": [e.to_dict() for e in entities],
        "edges": [e.to_dict() for e in edges],
        "notes": notes,
        "timeline": timeline,
    }

    json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
