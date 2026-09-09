"""TTL-based result caching for plugin outputs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class ResultCache:
    """Cache plugin results with TTL to avoid redundant queries."""

    def __init__(self, base_dir: Path | None = None, ttl_hours: int = 24) -> None:
        self.base_dir = base_dir or Path.home() / ".deeplook"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "cache.db"
        self.ttl = timedelta(hours=ttl_hours)
        self._init_db()

    def _init_db(self) -> None:
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                plugin TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def make_key(plugin: str, target: str) -> str:
        raw = f"{plugin}:{target.lower().strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, plugin: str, target: str) -> dict[str, Any] | None:
        key = self.make_key(plugin, target)
        row = self.conn.execute(
            "SELECT result, expires_at FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        expires = datetime.fromisoformat(row[1])
        if datetime.now(UTC) > expires:
            self.conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self.conn.commit()
            return None
        return json.loads(row[0])

    def set(self, plugin: str, target: str, result: dict[str, Any]) -> None:
        key = self.make_key(plugin, target)
        now = datetime.now(UTC)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO cache (key, plugin, target, result, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                plugin,
                target,
                json.dumps(result),
                now.isoformat(),
                (now + self.ttl).isoformat(),
            ),
        )
        self.conn.commit()

    def invalidate(self, plugin: str | None = None, target: str | None = None) -> int:
        if plugin and target:
            key = self.make_key(plugin, target)
            cursor = self.conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        elif plugin:
            cursor = self.conn.execute("DELETE FROM cache WHERE plugin = ?", (plugin,))
        elif target:
            cursor = self.conn.execute("DELETE FROM cache WHERE target = ?", (target,))
        else:
            cursor = self.conn.execute("DELETE FROM cache")
        self.conn.commit()
        return cursor.rowcount

    def stats(self) -> dict[str, Any]:
        total = self.conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        now = datetime.now(UTC).isoformat()
        valid = self.conn.execute(
            "SELECT COUNT(*) FROM cache WHERE expires_at > ?", (now,)
        ).fetchone()[0]
        return {"total_entries": total, "valid_entries": valid, "expired_entries": total - valid}

    def cleanup(self) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = self.conn.execute("DELETE FROM cache WHERE expires_at <= ?", (now,))
        self.conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self.conn.close()
