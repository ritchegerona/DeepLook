"""Relationship (edge) model for DeepLook OSINT framework."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class RelationshipType(StrEnum):
    RESOLVES_TO = "resolves_to"
    REVERSE_DNS = "reverse_dns"
    REGISTRANT = "registrant"
    MX_RECORD = "mx_record"
    NS_RECORD = "ns_record"
    SUBDOMAIN_OF = "subdomain_of"
    LINKS_TO = "links_to"
    PROFILE_ON = "profile_on"
    CONTACT_EMAIL = "contact_email"
    HOSTED_ON = "hosted_on"
    CERT_ISSUED_TO = "cert_issued_to"
    ASSOCIATED_WITH = "associated_with"
    REDIRECTS_TO = "redirects_to"
    USES_TECH = "uses_tech"
    BREACHED_IN = "breached_in"
    OWNED_BY = "owned_by"
    SIMILAR_TO = "similar_to"
    MENTIONED_IN = "mentioned_in"


RELATIONSHIP_LABELS = {
    RelationshipType.RESOLVES_TO: "resolves to",
    RelationshipType.REVERSE_DNS: "reverse DNS",
    RelationshipType.REGISTRANT: "registrant",
    RelationshipType.MX_RECORD: "MX record",
    RelationshipType.NS_RECORD: "NS record",
    RelationshipType.SUBDOMAIN_OF: "subdomain of",
    RelationshipType.LINKS_TO: "links to",
    RelationshipType.PROFILE_ON: "profile on",
    RelationshipType.CONTACT_EMAIL: "contact email",
    RelationshipType.HOSTED_ON: "hosted on",
    RelationshipType.CERT_ISSUED_TO: "cert issued to",
    RelationshipType.ASSOCIATED_WITH: "associated with",
    RelationshipType.REDIRECTS_TO: "redirects to",
    RelationshipType.USES_TECH: "uses tech",
    RelationshipType.BREACHED_IN: "breached in",
    RelationshipType.OWNED_BY: "owned by",
    RelationshipType.SIMILAR_TO: "similar to",
    RelationshipType.MENTIONED_IN: "mentioned in",
}


@dataclass
class Edge:
    source_id: str
    target_id: str
    relationship: RelationshipType
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidence: float = 100.0
    source_plugin: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Confidence is stored on a 0-100 scale. Plugins historically passed either
        # fractions (0.0-1.0, e.g. 0.8) or percentages (e.g. 80.0), so normalize
        # fractions up to keep the stored/rendered value consistent.
        if 0 < self.confidence <= 1:
            self.confidence = round(self.confidence * 100, 1)

    @property
    def label(self) -> str:
        return RELATIONSHIP_LABELS.get(self.relationship, self.relationship.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "source_plugin": self.source_plugin,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Edge:
        edge = cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relationship=RelationshipType(data["relationship"]),
            id=data.get("id", str(uuid.uuid4())),
            confidence=data.get("confidence", 100.0),
            source_plugin=data.get("source_plugin", ""),
        )
        if "first_seen" in data:
            edge.first_seen = datetime.fromisoformat(data["first_seen"])
        if "last_seen" in data:
            edge.last_seen = datetime.fromisoformat(data["last_seen"])
        edge.metadata = data.get("metadata", {})
        return edge

    def __hash__(self) -> int:
        return hash((self.source_id, self.target_id, self.relationship))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Edge):
            return NotImplemented
        return (
            self.source_id == other.source_id
            and self.target_id == other.target_id
            and self.relationship == other.relationship
        )
