"""MITRE ATT&CK technique mapping for DeepLook findings.

DeepLook is an open-source collection and analysis tool: the techniques it
exercises sit mostly in the ATT&CK **Reconnaissance** and **Resource
Development** tactics. This module maps the plugin that produced a finding
(via entity provenance) to the ATT&CK techniques it supports, and aggregates
technique coverage across a workspace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "tactic": self.tactic, "url": self.url}


def _technique(tid: str, name: str, tactic: str) -> Technique:
    path = "/".join(tid.split("."))
    return Technique(tid, name, tactic, f"https://attack.mitre.org/techniques/{path}/")


_RECON = "Reconnaissance"
_RESDEV = "Resource Development"

TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in [
        # Reconnaissance
        _technique("T1595", "Active Scanning", _RECON),
        _technique("T1595.001", "Scanning IP Blocks", _RECON),
        _technique("T1595.002", "Vulnerability Scanning", _RECON),
        _technique("T1592", "Gather Victim Host Information", _RECON),
        _technique("T1592.002", "Software", _RECON),
        _technique("T1590", "Gather Victim Network Information", _RECON),
        _technique("T1590.001", "Domain Properties", _RECON),
        _technique("T1590.002", "DNS", _RECON),
        _technique("T1590.004", "Network Topology", _RECON),
        _technique("T1590.005", "IP Addresses", _RECON),
        _technique("T1589", "Gather Victim Identity Information", _RECON),
        _technique("T1589.001", "Credentials", _RECON),
        _technique("T1589.002", "Email Addresses", _RECON),
        _technique("T1589.003", "Employee Names", _RECON),
        _technique("T1598", "Phishing for Information", _RECON),
        _technique("T1598.003", "Spearphishing Link", _RECON),
        _technique("T1596", "Search Open Technical Databases", _RECON),
        _technique("T1596.001", "DNS/Passive DNS", _RECON),
        _technique("T1596.002", "WHOIS", _RECON),
        _technique("T1596.003", "Digital Certificates", _RECON),
        _technique("T1596.005", "Scan Databases", _RECON),
        _technique("T1593", "Search Open Websites/Domains", _RECON),
        _technique("T1593.001", "Social Media", _RECON),
        _technique("T1593.002", "Search Engines", _RECON),
        _technique("T1593.003", "Code Repositories", _RECON),
        _technique("T1594", "Search Victim-Owned Websites", _RECON),
        _technique("T1597", "Search Closed Sources", _RECON),
        _technique("T1597.001", "Threat Intel Vendors", _RECON),
        # Resource Development
        _technique("T1583", "Acquire Infrastructure", _RESDEV),
        _technique("T1583.001", "Domains", _RESDEV),
        _technique("T1583.006", "Web Services", _RESDEV),
        _technique("T1584", "Compromise Infrastructure", _RESDEV),
        _technique("T1588", "Obtain Capabilities", _RESDEV),
        _technique("T1588.006", "Vulnerabilities", _RESDEV),
    ]
}


PLUGIN_TECHNIQUE_MAP: dict[str, list[str]] = {
    "domain-whois": ["T1596.002", "T1590.001"],
    "domain-dns": ["T1596.001", "T1590.002"],
    "domain-subdomain": ["T1596.003", "T1590.001"],
    "domain-web": ["T1594"],
    "crtsh": ["T1596.003"],
    "ip-geoloc": ["T1590.005"],
    "ip-revdns": ["T1596.001", "T1590.002"],
    "ip-ports": ["T1595.001", "T1596.005"],
    "ip-whois": ["T1596.002", "T1590.005"],
    "username-social": ["T1593.001", "T1589.003"],
    "email-syntax": ["T1589.002"],
    "email-mx": ["T1589.002", "T1590.002"],
    "email-breach": ["T1589.001", "T1597.001"],
    "phone-lookup": ["T1589.003"],
    "hash-lookup": ["T1596.005"],
    "btc-balance": ["T1583.001"],
    "web-tech": ["T1592.002"],
    "web-headers": ["T1592.002"],
    "web-cert": ["T1596.003"],
    "web-links": ["T1594"],
    "web-emails": ["T1589.002"],
    "web-sitemap": ["T1594"],
    "web-robots": ["T1594"],
    "web-redirects": ["T1594", "T1590.004"],
    "web-meta": ["T1592.002"],
    "web-dns-extra": ["T1596.001", "T1590.002"],
    "breach-domain": ["T1596.005", "T1597.001"],
    "breach-ip": ["T1596.005", "T1597.001"],
    "malware-hash": ["T1596.005", "T1597.001"],
    "cve-check": ["T1595.002", "T1588.006"],
    "ssl-vuln": ["T1595.002", "T1592.002"],
    "dns-security": ["T1590.002", "T1596.001"],
    "header-security": ["T1592.002"],
    "email-security": ["T1590.002", "T1589.002"],
    "subdomain-takeover": ["T1584", "T1590.001"],
    "exposed-services": ["T1595.002", "T1594"],
    "sensitive-files": ["T1594", "T1593.002"],
    "api-exposure": ["T1594", "T1595.002"],
}


ENTITY_TYPE_TECHNIQUES: dict[EntityType, list[str]] = {
    EntityType.DOMAIN: ["T1590.001", "T1596.002"],
    EntityType.SUBDOMAIN: ["T1590.001", "T1596.003"],
    EntityType.IP: ["T1590.005"],
    EntityType.CERT: ["T1596.003"],
    EntityType.EMAIL: ["T1589.002"],
    EntityType.USERNAME: ["T1589.003", "T1593.001"],
    EntityType.HASH: ["T1596.005"],
    EntityType.URL: ["T1594"],
    EntityType.ASN: ["T1590.004"],
    EntityType.ORG: ["T1590.004"],
    EntityType.BTC: ["T1583.001"],
    EntityType.PHONE: ["T1589.003"],
}


@dataclass
class TechniqueUsage:
    technique: Technique
    entities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {**self.technique.to_dict(), "entity_count": len(self.entities), "entities": self.entities}


@dataclass
class AttackReport:
    entity_count: int
    techniques: list[TechniqueUsage] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)

    @property
    def tactics(self) -> list[str]:
        return sorted({u.technique.tactic for u in self.techniques})

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_count": self.entity_count,
            "technique_count": len(self.techniques),
            "tactics": self.tactics,
            "techniques": [u.to_dict() for u in self.techniques],
            "unmapped": self.unmapped,
        }


def list_techniques() -> list[dict[str, Any]]:
    """Return the full technique registry used for mapping."""
    return [t.to_dict() for t in sorted(TECHNIQUES.values(), key=lambda t: t.id)]


def techniques_for_plugin(plugin_name: str) -> list[str]:
    """Return the ATT&CK technique IDs supported by a plugin."""
    return list(PLUGIN_TECHNIQUE_MAP.get(plugin_name, []))


def techniques_for_entity(entity: Entity) -> list[str]:
    """Resolve ATT&CK technique IDs for an entity via provenance, type fallback."""
    ids: list[str] = []
    for provenance in entity.provenance:
        for tid in techniques_for_plugin(provenance.source):
            if tid not in ids:
                ids.append(tid)
    if not ids:
        ids = list(ENTITY_TYPE_TECHNIQUES.get(entity.type, []))
    return ids


def map_entities(entities: list[Entity]) -> AttackReport:
    """Aggregate ATT&CK technique coverage for a list of entities."""
    usage: dict[str, TechniqueUsage] = {}
    unmapped: list[str] = []

    for entity in entities:
        ids = techniques_for_entity(entity)
        if not ids:
            unmapped.append(entity.value)
            continue
        for tid in ids:
            technique = TECHNIQUES.get(tid)
            if technique is None:
                continue
            entry = usage.setdefault(tid, TechniqueUsage(technique=technique))
            if entity.value not in entry.entities:
                entry.entities.append(entity.value)

    ordered = sorted(usage.values(), key=lambda u: (u.technique.tactic, u.technique.id))
    return AttackReport(entity_count=len(entities), techniques=ordered, unmapped=unmapped)


def map_workspace(workspace: Workspace, entities: list[Entity] | None = None) -> AttackReport:
    """Map ATT&CK coverage for a workspace (or a supplied entity subset)."""
    if entities is None:
        entities = workspace.all_entities()
    return map_entities(entities)


def annotate_entities(workspace: Workspace, entities: list[Entity] | None = None) -> AttackReport:
    """Map coverage and persist technique IDs into ``entity.metadata["attack"]``."""
    if entities is None:
        entities = workspace.all_entities()
    for entity in entities:
        ids = techniques_for_entity(entity)
        if ids:
            entity.metadata["attack"] = ids
            workspace.add_entity(entity)
    return map_entities(entities)
