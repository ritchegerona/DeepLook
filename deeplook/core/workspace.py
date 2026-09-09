"""SQLite-backed workspace/case management."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType, ProvenanceEntry
from deeplook.core.graph import IntelGraph


class Workspace:
    """Persistent investigation workspace backed by SQLite."""

    def __init__(self, name: str, base_dir: Path | None = None) -> None:
        self.name = name
        self.base_dir = base_dir or Path.home() / ".deeplook" / "workspaces"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / f"{name}.db"
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confidence REAL DEFAULT 100.0,
                notes TEXT DEFAULT '[]',
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                provenance TEXT DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confidence REAL DEFAULT 100.0,
                source_plugin TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY (source_id) REFERENCES entities(id),
                FOREIGN KEY (target_id) REFERENCES entities(id)
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (entity_id) REFERENCES entities(id)
            );
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                target TEXT DEFAULT '',
                details TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                targets TEXT DEFAULT '[]',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                plugin_count INTEGER DEFAULT 0,
                entity_count INTEGER DEFAULT 0
            );
            """
        )
        self.conn.commit()

    def add_entity(self, entity: Entity) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO entities
            (id, type, value, first_seen, last_seen, confidence, notes, tags, metadata, provenance)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity.id,
                entity.type.value,
                entity.value,
                entity.first_seen.isoformat(),
                entity.last_seen.isoformat(),
                entity.confidence,
                json.dumps(entity.notes),
                json.dumps(entity.tags),
                json.dumps(entity.metadata),
                json.dumps(
                    [
                        {
                            "source": p.source,
                            "queried_at": p.queried_at.isoformat(),
                            "confidence": p.confidence,
                        }
                        for p in entity.provenance
                    ]
                ),
            ),
        )
        self.conn.commit()

    def add_edge(self, edge: Edge) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO edges
            (id, source_id, target_id, relationship,
             first_seen, last_seen, confidence,
             source_plugin, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                edge.id,
                edge.source_id,
                edge.target_id,
                edge.relationship.value,
                edge.first_seen.isoformat(),
                edge.last_seen.isoformat(),
                edge.confidence,
                edge.source_plugin,
                json.dumps(edge.metadata),
            ),
        )
        self.conn.commit()

    def get_entity(self, entity_id: str) -> Entity | None:
        row = self.conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        return self._row_to_entity(row) if row else None

    def find_entity_by_value(self, value: str) -> Entity | None:
        row = self.conn.execute(
            "SELECT * FROM entities WHERE LOWER(value) = LOWER(?)", (value,)
        ).fetchone()
        return self._row_to_entity(row) if row else None

    def find_entities(self, query: str) -> list[Entity]:
        rows = self.conn.execute(
            "SELECT * FROM entities WHERE LOWER(value) LIKE LOWER(?)",
            (f"%{query}%",),
        ).fetchall()
        return [self._row_to_entity(r) for r in rows]

    def all_entities(self) -> list[Entity]:
        rows = self.conn.execute("SELECT * FROM entities ORDER BY type, value").fetchall()
        return [self._row_to_entity(r) for r in rows]

    def all_edges(self) -> list[Edge]:
        rows = self.conn.execute("SELECT * FROM edges ORDER BY first_seen").fetchall()
        return [self._row_to_edge(r) for r in rows]

    def entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        rows = self.conn.execute(
            "SELECT * FROM entities WHERE type = ? ORDER BY value", (entity_type.value,)
        ).fetchall()
        return [self._row_to_entity(r) for r in rows]

    def edges_for_entity(self, entity_id: str) -> list[Edge]:
        rows = self.conn.execute(
            "SELECT * FROM edges WHERE source_id = ? OR target_id = ?",
            (entity_id, entity_id),
        ).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def add_note(self, entity_id: str | None, content: str) -> None:
        self.conn.execute(
            "INSERT INTO notes (entity_id, content, created_at) VALUES (?, ?, ?)",
            (entity_id, content, datetime.now(UTC).isoformat()),
        )
        self.conn.commit()

    def get_notes(self, entity_id: str | None = None) -> list[dict[str, Any]]:
        if entity_id:
            rows = self.conn.execute(
                "SELECT * FROM notes WHERE entity_id = ? ORDER BY created_at",
                (entity_id,),
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM notes ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def add_timeline_event(self, event: str, target: str = "", details: dict | None = None) -> None:
        self.conn.execute(
            "INSERT INTO timeline (timestamp, event, target, details) VALUES (?, ?, ?, ?)",
            (
                datetime.now(UTC).isoformat(),
                event,
                target,
                json.dumps(details or {}),
            ),
        )
        self.conn.commit()

    def get_timeline(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM timeline ORDER BY timestamp").fetchall()
        return [dict(r) for r in rows]

    def log_scan(self, command: str, targets: list[str], plugin_count: int = 0) -> int:
        cursor = self.conn.execute(
            "INSERT INTO scan_history "
            "(command, targets, started_at, plugin_count) "
            "VALUES (?, ?, ?, ?)",
            (command, json.dumps(targets), datetime.now(UTC).isoformat(), plugin_count),
        )
        self.conn.commit()
        return cursor.lastrowid or 0

    def finish_scan(self, scan_id: int, entity_count: int) -> None:
        self.conn.execute(
            "UPDATE scan_history SET finished_at = ?, entity_count = ? WHERE id = ?",
            (datetime.now(UTC).isoformat(), entity_count, scan_id),
        )
        self.conn.commit()

    def to_graph(self) -> IntelGraph:
        graph = IntelGraph()
        for entity in self.all_entities():
            graph.add_entity(entity)
        for edge in self.all_edges():
            graph.add_edge(edge)
        return graph

    def search(self, query: str) -> dict[str, Any]:
        entities = self.find_entities(query)
        edges = []
        for entity in entities:
            edges.extend(self.edges_for_entity(entity.id))
        notes = self.conn.execute(
            "SELECT * FROM notes WHERE LOWER(content) LIKE LOWER(?)",
            (f"%{query}%",),
        ).fetchall()
        return {
            "entities": entities,
            "edges": edges,
            "notes": [dict(n) for n in notes],
        }

    def close(self) -> None:
        self.conn.close()

    def _row_to_entity(self, row: sqlite3.Row) -> Entity:
        entity = Entity(
            type=EntityType(row["type"]),
            value=row["value"],
            id=row["id"],
            confidence=row["confidence"],
        )
        entity.first_seen = datetime.fromisoformat(row["first_seen"])
        entity.last_seen = datetime.fromisoformat(row["last_seen"])
        entity.notes = json.loads(row["notes"])
        entity.tags = json.loads(row["tags"])
        entity.metadata = json.loads(row["metadata"])
        for p in json.loads(row["provenance"]):
            entry = ProvenanceEntry(
                source=p["source"],
                confidence=p.get("confidence", 1.0),
            )
            if "queried_at" in p:
                entry.queried_at = datetime.fromisoformat(p["queried_at"])
            entity.provenance.append(entry)
        return entity

    def _row_to_edge(self, row: sqlite3.Row) -> Edge:
        edge = Edge(
            source_id=row["source_id"],
            target_id=row["target_id"],
            relationship=RelationshipType(row["relationship"]),
            id=row["id"],
            confidence=row["confidence"],
            source_plugin=row["source_plugin"],
        )
        edge.first_seen = datetime.fromisoformat(row["first_seen"])
        edge.last_seen = datetime.fromisoformat(row["last_seen"])
        edge.metadata = json.loads(row["metadata"])
        return edge

    @classmethod
    def list_workspaces(cls, base_dir: Path | None = None) -> list[str]:
        base = base_dir or Path.home() / ".deeplook" / "workspaces"
        if not base.exists():
            return []
        return [f.stem for f in base.glob("*.db")]

    @classmethod
    def create(cls, name: str, base_dir: Path | None = None) -> Workspace:
        ws = cls(name, base_dir)
        ws.add_timeline_event(f"Workspace '{name}' created")
        return ws
