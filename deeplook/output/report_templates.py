"""Report template definitions for DeepLook exports."""

from __future__ import annotations

from dataclasses import dataclass, field

from deeplook.core.entity import EntityType


@dataclass
class ReportTemplate:
    name: str
    description: str
    entity_types: list[EntityType]
    columns: dict[EntityType, list[str]]
    sheets: list[str] = field(default_factory=lambda: ["Summary", "Entities"])

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "entity_types": [t.value for t in self.entity_types],
            "sheets": self.sheets,
        }


_ALL_ENTITY_COLUMNS = {
    EntityType.DOMAIN: ["Value", "Registrar", "Created", "Expires", "Name Servers", "Confidence"],
    EntityType.IP: ["Value", "ASN", "Organization", "Country", "ISP", "Confidence"],
    EntityType.EMAIL: ["Value", "Valid", "Disposable", "Provider", "Confidence"],
    EntityType.USERNAME: ["Value", "Platform", "URL", "Status", "Confidence"],
    EntityType.HASH: ["Value", "Type", "Confidence"],
    EntityType.URL: ["Value", "Status", "Confidence"],
    EntityType.PHONE: ["Value", "Country", "Type", "Confidence"],
    EntityType.BTC: ["Value", "Balance", "Confidence"],
    EntityType.SUBDOMAIN: ["Value", "Confidence"],
    EntityType.CERT: ["Value", "Issuer", "Expiry", "Confidence"],
    EntityType.ASN: ["Value", "Name", "Country", "Confidence"],
    EntityType.ORG: ["Value", "Country", "Confidence"],
}

_IOC_ENTITY_TYPES = [
    EntityType.IP,
    EntityType.DOMAIN,
    EntityType.HASH,
    EntityType.URL,
    EntityType.EMAIL,
]

_TEMPLATES: dict[str, ReportTemplate] = {
    "executive": ReportTemplate(
        name="executive",
        description="High-level summary for executives with key IOCs only",
        entity_types=_IOC_ENTITY_TYPES,
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["Summary", "IOCs"],
    ),
    "technical": ReportTemplate(
        name="technical",
        description="Full technical report with all entities, relationships, and metadata",
        entity_types=list(EntityType),
        columns=_ALL_ENTITY_COLUMNS,
        sheets=[
            "Summary",
            "Entities",
            "Relationships",
            "Domain Details",
            "IP Details",
            "Username Results",
            "Email Analysis",
            "IOCs",
            "Correlation",
            "ATT&CK",
            "Watchlist",
            "Ingestion",
            "Timeline",
            "Notes",
        ],
    ),
    "ioc": ReportTemplate(
        name="ioc",
        description="Indicator of Compromise export for sharing",
        entity_types=_IOC_ENTITY_TYPES,
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["IOCs"],
    ),
    "phishing": ReportTemplate(
        name="phishing",
        description="Phishing investigation report focusing on domains, emails, and URLs",
        entity_types=[
            EntityType.DOMAIN,
            EntityType.EMAIL,
            EntityType.URL,
            EntityType.IP,
            EntityType.SUBDOMAIN,
        ],
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["Summary", "Entities", "Domain Details", "IOCs", "Correlation", "Timeline"],
    ),
    "threat_actor": ReportTemplate(
        name="threat_actor",
        description="Threat actor profiling report with infrastructure and identity mapping",
        entity_types=[
            EntityType.DOMAIN,
            EntityType.IP,
            EntityType.EMAIL,
            EntityType.USERNAME,
            EntityType.HASH,
            EntityType.ORG,
        ],
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["Summary", "Entities", "Relationships", "IP Details", "IOCs", "Correlation", "ATT&CK"],
    ),
    "infrastructure": ReportTemplate(
        name="infrastructure",
        description="Infrastructure mapping report focused on hosting and network relationships",
        entity_types=[
            EntityType.IP,
            EntityType.DOMAIN,
            EntityType.ASN,
            EntityType.ORG,
            EntityType.CERT,
        ],
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["Summary", "Entities", "Domain Details", "IP Details", "Correlation", "ATT&CK"],
    ),
    "monitoring": ReportTemplate(
        name="monitoring",
        description="Watchlist and ingestion monitoring report with tracked indicators",
        entity_types=_IOC_ENTITY_TYPES,
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["Summary", "Watchlist", "Ingestion", "IOCs", "ATT&CK", "Timeline"],
    ),
    "custom": ReportTemplate(
        name="custom",
        description="Blank template for custom sheet selection",
        entity_types=list(EntityType),
        columns=_ALL_ENTITY_COLUMNS,
        sheets=["Summary"],
    ),
}


def get_template(name: str) -> ReportTemplate:
    if name not in _TEMPLATES:
        raise ValueError(f"Unknown template: {name}. Available: {', '.join(_TEMPLATES.keys())}")
    return _TEMPLATES[name]


def list_templates() -> list[dict]:
    return [t.to_dict() for t in _TEMPLATES.values()]
