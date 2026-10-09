"""Entity model for DeepLook OSINT framework."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EntityType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    HASH = "hash"
    BTC = "btc"
    URL = "url"
    SUBDOMAIN = "subdomain"
    CERT = "cert"
    ASN = "asn"
    ORG = "org"


ENTITY_COLORS = {
    EntityType.DOMAIN: "green",
    EntityType.IP: "blue",
    EntityType.EMAIL: "orange3",
    EntityType.USERNAME: "magenta",
    EntityType.PHONE: "yellow",
    EntityType.HASH: "red",
    EntityType.BTC: "cyan",
    EntityType.URL: "bright_green",
    EntityType.SUBDOMAIN: "bright_green",
    EntityType.CERT: "bright_yellow",
    EntityType.ASN: "bright_blue",
    EntityType.ORG: "bright_magenta",
}


@dataclass
class ProvenanceEntry:
    source: str
    queried_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidence: float = 1.0
    raw_data: dict[str, Any] | None = None


@dataclass
class Entity:
    type: EntityType
    value: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidence: float = 100.0
    provenance: list[ProvenanceEntry] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_provenance(self, source: str, confidence: float = 1.0, raw_data: dict[str, Any] | None = None) -> None:
        self.provenance.append(ProvenanceEntry(source=source, confidence=confidence, raw_data=raw_data))
        self.last_seen = datetime.now(UTC)
        avg_conf = sum(p.confidence for p in self.provenance) / len(self.provenance)
        self.confidence = round(avg_conf * 100, 1)

    def add_note(self, note: str) -> None:
        self.notes.append(f"[{datetime.now(UTC).isoformat()}] {note}")

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    @property
    def color(self) -> str:
        return ENTITY_COLORS.get(self.type, "white")

    @property
    def display_value(self) -> str:
        return self.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "provenance": [
                {
                    "source": p.source,
                    "queried_at": p.queried_at.isoformat(),
                    "confidence": p.confidence,
                }
                for p in self.provenance
            ],
            "notes": self.notes,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entity:
        entity = cls(
            type=EntityType(data["type"]),
            value=data["value"],
            id=data.get("id", str(uuid.uuid4())),
            confidence=data.get("confidence", 100.0),
        )
        if "first_seen" in data:
            entity.first_seen = datetime.fromisoformat(data["first_seen"])
        if "last_seen" in data:
            entity.last_seen = datetime.fromisoformat(data["last_seen"])
        entity.notes = data.get("notes", [])
        entity.tags = data.get("tags", [])
        entity.metadata = data.get("metadata", {})
        for p in data.get("provenance", []):
            entry = ProvenanceEntry(
                source=p["source"],
                confidence=p.get("confidence", 1.0),
            )
            if "queried_at" in p:
                entry.queried_at = datetime.fromisoformat(p["queried_at"])
            entity.provenance.append(entry)
        return entity

    def __hash__(self) -> int:
        return hash((self.type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Entity):
            return NotImplemented
        return self.type == other.type and self.value.lower() == other.value.lower()


# --- Entity Detection ---

_IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[1-9]\d{6,14}$")
_BTC_RE = re.compile(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


# --- Defang / Refang ---

_DEFANG_SCHEMES = (("https", "hxxps"), ("http", "hxxp"), ("ftp", "fxp"))

_REFANG_PAIRS = (
    ("[://]", "://"),
    ("[//]", "//"),
    ("[:]", ":"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("[@]", "@"),
    ("[at]", "@"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
)


def defang(value: str) -> str:
    """Neutralize an indicator for safe sharing (``http`` -> ``hxxp``, ``.`` -> ``[.]``)."""
    result = value.strip().replace("://", "[://]").replace(".", "[.]").replace("@", "[@]")
    for scheme, replacement in _DEFANG_SCHEMES:
        result = result.replace(scheme, replacement)
    return result


def refang(value: str) -> str:
    """Restore a defanged indicator to its original form."""
    result = value.strip()
    for token, replacement in _REFANG_PAIRS:
        for variant in {token, token.upper(), token.capitalize()}:
            result = result.replace(variant, replacement)
    return result


def detect_entity_type(value: str) -> EntityType | None:
    """Auto-detect entity type from a string value."""
    value = refang(value)

    if _IP_RE.match(value):
        return EntityType.IP
    if _EMAIL_RE.match(value):
        return EntityType.EMAIL
    if _HASH_RE.match(value):
        return EntityType.HASH
    if _BTC_RE.match(value):
        return EntityType.BTC
    if _PHONE_RE.match(value):
        return EntityType.PHONE
    if _URL_RE.match(value):
        return EntityType.URL
    if _DOMAIN_RE.match(value):
        return EntityType.DOMAIN
    return None


def create_entity(value: str, entity_type: EntityType | None = None, **kwargs: Any) -> Entity:
    """Create an entity, refanging and auto-detecting type if not specified."""
    value = refang(value)
    if entity_type is None:
        detected = detect_entity_type(value)
        if detected is None:
            raise ValueError(f"Cannot detect entity type for: {value}")
        entity_type = detected
    return Entity(type=entity_type, value=value, **kwargs)
