"""IOC feed ingestion for DeepLook workspaces.

Supports plain-text (optionally defanged) indicator lists, CSV, STIX 2.1
bundles, and MISP event JSON. Indicators are refanged, de-duplicated against
the workspace, tagged, and stored with provenance so the source feed is
traceable.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deeplook.core.entity import create_entity, refang
from deeplook.core.workspace import Workspace

_HEADER_TOKENS = {"value", "ioc", "indicator", "type", "domain", "ip", "url", "email", "hash"}


@dataclass
class IngestResult:
    source: str
    format: str
    total: int = 0
    added: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    samples: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "format": self.format,
            "total": self.total,
            "added": self.added,
            "skipped": self.skipped,
            "errors": self.errors,
            "samples": self.samples,
        }


def detect_format(path: Path, content: str) -> str:
    """Best-effort format detection from the file suffix and content."""
    suffix = path.suffix.lower()
    if suffix == ".stix":
        return "stix"
    if suffix == ".csv":
        return "csv"

    stripped = content.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return "text"
        if isinstance(data, dict) and data.get("type") == "bundle":
            return "stix"
        if isinstance(data, dict) and ("Attribute" in data or "Event" in data or "response" in data):
            return "misp"
        if isinstance(data, list) and data and isinstance(data[0], dict) and "Attribute" in data[0]:
            return "misp"
        return "misp"
    return "text"


def parse_text(content: str) -> list[str]:
    """Parse a plain-text list of indicators, one per line, ``#`` comments allowed."""
    values: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line:
            values.append(line)
    return values


def parse_csv(content: str) -> list[str]:
    """Parse the first column of a CSV, skipping a recognised header row."""
    values: list[str] = []
    reader = csv.reader(io.StringIO(content))
    for row_idx, row in enumerate(reader):
        if not row:
            continue
        token = row[0].strip()
        if not token:
            continue
        if row_idx == 0 and token.lower() in _HEADER_TOKENS:
            continue
        values.append(token)
    return values


def parse_stix(content: str) -> list[str]:
    """Extract indicator values from a STIX 2.1 bundle."""
    data = json.loads(content)
    objects = data.get("objects", []) if isinstance(data, dict) else []
    values: list[str] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "indicator":
            values.extend(re.findall(r"=\s*'([^']+)'", obj.get("pattern", "")))
        elif obj.get("type") in {"domain-name", "ipv4-addr", "ipv6-addr", "url"} and obj.get("value"):
            values.append(obj["value"])
        if isinstance(obj.get("hashes"), dict):
            values.extend(str(h) for h in obj["hashes"].values())
    return values


def parse_misp(content: str) -> list[str]:
    """Extract attribute values from MISP event JSON (single event, list, or response)."""
    data = json.loads(content)
    if isinstance(data, list):
        events = data
    elif isinstance(data, dict):
        if isinstance(data.get("response"), list):
            events = data["response"]
        elif "Event" in data:
            event = data["Event"]
            events = event if isinstance(event, list) else [event]
        else:
            events = [data]
    else:
        return []

    values: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        attributes = event.get("Attribute", [])
        if isinstance(attributes, dict):
            attributes = [attributes]
        for attribute in attributes:
            if isinstance(attribute, dict) and attribute.get("value"):
                values.append(str(attribute["value"]))
        for nested in event.get("Object", []) or []:
            if isinstance(nested, dict):
                for attribute in nested.get("Attribute", []) or []:
                    if isinstance(attribute, dict) and attribute.get("value"):
                        values.append(str(attribute["value"]))
    return values


_PARSERS: dict[str, Callable[[str], list[str]]] = {
    "text": parse_text,
    "csv": parse_csv,
    "stix": parse_stix,
    "misp": parse_misp,
}


def ingest_file(
    workspace: Workspace,
    path: Path,
    fmt: str = "auto",
    tags: list[str] | None = None,
    source_name: str | None = None,
) -> IngestResult:
    """Load indicators from ``path`` into ``workspace``."""
    path = Path(path)
    content = path.read_text(encoding="utf-8", errors="replace")
    if fmt == "auto":
        fmt = detect_format(path, content)

    result = IngestResult(source=source_name or path.name, format=fmt)
    parser = _PARSERS.get(fmt)
    if parser is None:
        result.errors.append(f"unsupported format: {fmt}")
        return result

    try:
        values = parser(content)
    except Exception as exc:  # noqa: BLE001 - surface the parse failure to the caller
        result.errors.append(f"failed to parse {fmt}: {exc}")
        return result

    _load_values(workspace, values, result, tags)
    return result


def _load_values(workspace: Workspace, values: list[str], result: IngestResult, tags: list[str] | None) -> None:
    seen: set[tuple[str, str]] = set()
    existing = {e.value.lower() for e in workspace.all_entities()}

    for raw in values:
        token = raw.strip()
        if not token:
            continue
        result.total += 1
        try:
            entity = create_entity(refang(token))
        except ValueError:
            result.errors.append(f"unrecognized indicator: {token}")
            result.skipped += 1
            continue

        key = (entity.type.value, entity.value.lower())
        if key in seen or entity.value.lower() in existing:
            result.skipped += 1
            continue

        seen.add(key)
        entity.add_provenance(source=f"ingest:{result.source}", confidence=0.7)
        entity.add_tag("ingested")
        for tag in tags or []:
            entity.add_tag(tag)
        workspace.add_entity(entity)
        existing.add(entity.value.lower())
        result.added += 1
        if len(result.samples) < 25:
            result.samples.append({"type": entity.type.value, "value": entity.value})

    workspace.add_timeline_event(
        "IOC ingestion",
        target=result.source,
        details={"format": result.format, "added": result.added, "skipped": result.skipped},
    )
