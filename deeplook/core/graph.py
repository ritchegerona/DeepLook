"""In-memory graph engine with ASCII/Unicode visualization."""

from __future__ import annotations

from collections import defaultdict

import networkx as nx
from rich.text import Text

from deeplook.core.edge import Edge
from deeplook.core.entity import ENTITY_COLORS, Entity, EntityType


class IntelGraph:
    """Directed graph of entities and their relationships."""

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._entities: dict[str, Entity] = {}
        self._edges: dict[str, Edge] = {}

    def add_entity(self, entity: Entity) -> None:
        self._entities[entity.id] = entity
        self._graph.add_node(
            entity.id,
            type=entity.type.value,
            value=entity.value,
            confidence=entity.confidence,
        )

    def add_edge(self, edge: Edge) -> None:
        self._edges[edge.id] = edge
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            relationship=edge.relationship.value,
            label=edge.label,
            confidence=edge.confidence,
        )

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def get_entity_by_value(self, entity_type: EntityType, value: str) -> Entity | None:
        for e in self._entities.values():
            if e.type == entity_type and e.value.lower() == value.lower():
                return e
        return None

    def find_entity(self, value: str) -> Entity | None:
        for e in self._entities.values():
            if e.value.lower() == value.lower():
                return e
        return None

    def get_neighbors(self, entity_id: str, direction: str = "both") -> list[tuple[Entity, Edge]]:
        results = []
        if direction in ("out", "both"):
            for _, target_id, data in self._graph.out_edges(entity_id, data=True):
                edge = self._find_edge(entity_id, target_id, data.get("relationship", ""))
                if edge and target_id in self._entities:
                    results.append((self._entities[target_id], edge))
        if direction in ("in", "both"):
            for source_id, _, data in self._graph.in_edges(entity_id, data=True):
                edge = self._find_edge(source_id, entity_id, data.get("relationship", ""))
                if edge and source_id in self._entities:
                    results.append((self._entities[source_id], edge))
        return results

    def _find_edge(self, source_id: str, target_id: str, relationship: str) -> Edge | None:
        for edge in self._edges.values():
            if edge.source_id == source_id and edge.target_id == target_id and edge.relationship.value == relationship:
                return edge
        return None

    def shortest_path(self, source_id: str, target_id: str) -> list[Entity] | None:
        try:
            path = nx.shortest_path(self._graph, source_id, target_id)
            return [self._entities[nid] for nid in path if nid in self._entities]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def centrality(self) -> dict[str, float]:
        if len(self._graph) == 0:
            return {}
        return nx.degree_centrality(self._graph)

    def communities(self) -> list[set[str]]:
        undirected = self._graph.to_undirected()
        return [set(c) for c in nx.community.greedy_modularity_communities(undirected)]

    @property
    def entity_count(self) -> int:
        return len(self._entities)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def entities(self) -> list[Entity]:
        return list(self._entities.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        return [e for e in self._entities.values() if e.type == entity_type]

    def render_ascii(self, center: str | None = None, max_depth: int = 3) -> Text:
        """Render the graph as ASCII/Unicode art."""
        if not self._entities:
            return Text("  (empty graph)\n")

        if center:
            center_entity = self.find_entity(center)
            if center_entity:
                return self._render_ego(center_entity.id, max_depth)

        return self._render_full()

    def _render_full(self) -> Text:
        text = Text()
        type_groups: dict[str, list[Entity]] = defaultdict(list)
        for entity in self._entities.values():
            type_groups[entity.type.value].append(entity)

        text.append("┌─── DeepLook Entity Graph ───┐\n", style="bold cyan")
        text.append(f"│ Entities: {self.entity_count}  Edges: {self.edge_count}\n\n")

        for etype, entities in sorted(type_groups.items()):
            color = ENTITY_COLORS.get(EntityType(etype), "white")
            text.append(f"  [{etype.upper()}]\n", style=f"bold {color}")
            for entity in sorted(entities, key=lambda e: e.value):
                text.append("    ● ", style=color)
                text.append(f"{entity.value}")
                text.append(f"  (conf: {entity.confidence:.0f}%)\n", style="dim")
                neighbors = self.get_neighbors(entity.id, "out")
                for neighbor, edge in neighbors[:5]:
                    ncolor = ENTITY_COLORS.get(neighbor.type, "white")
                    text.append(f"      └─{edge.label}→ ", style="dim")
                    text.append(f"{neighbor.value}\n", style=ncolor)
                if len(neighbors) > 5:
                    text.append(f"      └─ ... and {len(neighbors) - 5} more\n", style="dim")
            text.append("\n")

        return text

    def _render_ego(self, center_id: str, max_depth: int) -> Text:
        text = Text()
        center = self._entities[center_id]
        color = ENTITY_COLORS.get(center.type, "white")

        text.append("┌─── Ego Graph ───┐\n", style="bold cyan")
        text.append("│ Center: ", style="dim")
        text.append(f"{center.value}\n\n", style=f"bold {color}")

        visited: set[str] = set()
        self._render_node(text, center_id, 0, max_depth, visited, prefix="  ", is_last=True)

        return text

    def _render_node(
        self,
        text: Text,
        node_id: str,
        depth: int,
        max_depth: int,
        visited: set[str],
        prefix: str,
        is_last: bool,
    ) -> None:
        if depth > max_depth or node_id in visited:
            return
        visited.add(node_id)

        entity = self._entities.get(node_id)
        if entity is None:
            return

        connector = "└── " if is_last else "├── "
        color = ENTITY_COLORS.get(entity.type, "white")

        text.append(f"{prefix}{connector}", style="dim")
        text.append(f"{entity.value}", style=f"bold {color}")
        text.append(f" ({entity.type.value})\n", style="dim")

        neighbors = self.get_neighbors(node_id, "out")
        child_prefix = prefix + ("    " if is_last else "│   ")

        for i, (neighbor, edge) in enumerate(neighbors):
            is_last_child = i == len(neighbors) - 1
            text.append(f"{child_prefix}", style="dim")
            text.append(f"──{edge.label}→ ", style="dim")
            self._render_node(text, neighbor.id, depth + 1, max_depth, visited, child_prefix, is_last_child)

    def render_map(self, locations: dict[str, tuple[float, float]] | None = None) -> Text:
        """Render a simple ASCII world map with IP locations."""
        text = Text()
        text.append("┌─── Geo Map ───┐\n", style="bold cyan")

        ip_entities = self.entities_by_type(EntityType.IP)
        if not ip_entities:
            text.append("│ No IP entities in graph\n", style="dim")
            return text

        if locations:
            text.append("│ IP Locations:\n")
            for ip_entity in ip_entities:
                if ip_entity.value in locations:
                    lat, lon = locations[ip_entity.value]
                    text.append("│   ", style="dim")
                    text.append(f"{ip_entity.value}", style="blue")
                    text.append(f" → ({lat:.2f}, {lon:.2f})\n")
                else:
                    text.append("│   ", style="dim")
                    text.append(f"{ip_entity.value}", style="blue")
                    text.append(" → (unknown)\n", style="dim")
        else:
            text.append("│ No geolocation data available\n", style="dim")
            text.append("│ Run: deeplook ip <ip> --map\n", style="dim")

        return text

    def merge(self, other: IntelGraph) -> None:
        """Merge another graph into this one."""
        for entity in other.entities:
            if entity.id not in self._entities:
                self.add_entity(entity)
        for edge in other.edges:
            if edge.id not in self._edges:
                self.add_edge(edge)
