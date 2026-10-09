"""Rich table formatters for DeepLook OSINT results."""

from __future__ import annotations

from rich.table import Table
from rich.text import Text

from deeplook.core.edge import Edge
from deeplook.core.entity import ENTITY_COLORS, Entity
from deeplook.plugins.base import PluginResult


def _confidence_style(confidence: float) -> str:
    if confidence >= 80:
        return "bold green"
    if confidence >= 50:
        return "bold yellow"
    return "bold red"


def render_entity_table(entities: list[Entity], title: str = "Entities") -> Table:
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Type", style="bold")
    table.add_column("Value")
    table.add_column("Confidence", justify="right")
    table.add_column("Source")
    table.add_column("First Seen")

    for entity in entities:
        color = ENTITY_COLORS.get(entity.type, "white")
        source = entity.provenance[-1].source if entity.provenance else "-"
        table.add_row(
            Text(entity.type.value, style=color),
            entity.value,
            Text(f"{entity.confidence:.0f}%", style=_confidence_style(entity.confidence)),
            source,
            entity.first_seen.strftime("%Y-%m-%d %H:%M"),
        )

    return table


def render_edge_table(edges: list[Edge], entities: dict[str, Entity], title: str = "Relationships") -> Table:
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Source", style="bold")
    table.add_column("Relationship", style="dim")
    table.add_column("Target", style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Plugin")
    table.add_column("First Seen")

    for edge in edges:
        src = entities.get(edge.source_id)
        tgt = entities.get(edge.target_id)
        src_label = f"[{src.type.value}]{src.value}" if src else edge.source_id
        tgt_label = f"[{tgt.type.value}]{tgt.value}" if tgt else edge.target_id

        src_color = ENTITY_COLORS.get(src.type, "white") if src else "white"
        tgt_color = ENTITY_COLORS.get(tgt.type, "white") if tgt else "white"

        table.add_row(
            Text(src_label, style=src_color),
            edge.label,
            Text(tgt_label, style=tgt_color),
            Text(f"{edge.confidence:.0f}%", style=_confidence_style(edge.confidence)),
            edge.source_plugin or "-",
            edge.first_seen.strftime("%Y-%m-%d %H:%M"),
        )

    return table


def render_plugin_results(plugin_name: str, result: PluginResult) -> Table:
    table = Table(title=f"Plugin: {plugin_name}", show_lines=True, expand=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Entities found", str(len(result.entities)))
    table.add_row("Edges found", str(len(result.edges)))

    if result.warnings:
        table.add_row("Warnings", ", ".join(result.warnings))

    for key, value in result.metadata.items():
        table.add_row(key, str(value))

    return table
