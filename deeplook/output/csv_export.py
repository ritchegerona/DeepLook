"""CSV export for DeepLook workspaces."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from deeplook.core.workspace import Workspace


def export_csv(workspace: Workspace, output_path: Path | None = None, delimiter: str = ",") -> str:
    entities = workspace.all_entities()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter)
    writer.writerow(["type", "value", "confidence", "source", "first_seen", "last_seen", "notes"])

    for entity in entities:
        source = entity.provenance[-1].source if entity.provenance else ""
        notes_str = "; ".join(entity.notes) if entity.notes else ""
        writer.writerow(
            [
                entity.type.value,
                entity.value,
                f"{entity.confidence:.1f}",
                source,
                entity.first_seen.isoformat(),
                entity.last_seen.isoformat(),
                notes_str,
            ]
        )

    csv_str = output.getvalue()
    output.close()

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(csv_str, encoding="utf-8")

    return csv_str
