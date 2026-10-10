from __future__ import annotations

import whois  # type: ignore[import-untyped]

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class DomainWhois(OSINTPlugin):
    name = "domain-whois"
    description = "WHOIS/RDAP lookup for domain registration data"
    entity_types = [EntityType.DOMAIN]
    tags = ["passive", "registration"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        try:
            w = whois.whois(entity.value)

            entity.metadata["registrar"] = w.registrar
            entity.metadata["creation_date"] = str(w.creation_date) if w.creation_date else None
            entity.metadata["expiration_date"] = str(w.expiration_date) if w.expiration_date else None
            entity.metadata["status"] = w.status if isinstance(w.status, list) else [w.status] if w.status else []
            entity.metadata["name_servers"] = (
                w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            )
            entity.metadata["registrant"] = w.org or w.name
            entity.metadata["country"] = w.country
            entity.metadata["emails"] = w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []

            entity.add_provenance(source=self.name, confidence=0.9, raw_data={"whois_raw": str(w)})
            entity.add_tag("whois-looked-up")
            workspace.add_entity(entity)
            result.add_entity(entity)

            for ns in entity.metadata["name_servers"]:
                if not ns:
                    continue
                ns_lower = ns.strip().lower()
                ns_entity = Entity(type=EntityType.DOMAIN, value=ns_lower, confidence=85.0)
                ns_entity.add_provenance(source=self.name, confidence=0.85)
                workspace.add_entity(ns_entity)
                result.add_entity(ns_entity)

                ns_edge = Edge(
                    source_id=entity.id,
                    target_id=ns_entity.id,
                    relationship=RelationshipType.NS_RECORD,
                    source_plugin=self.name,
                    confidence=85.0,
                )
                workspace.add_edge(ns_edge)
                result.add_edge(ns_edge)

            if w.emails:
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                for email in emails:
                    if not email or "@" not in email:
                        continue
                    email_entity = Entity(type=EntityType.EMAIL, value=email.strip().lower(), confidence=80.0)
                    email_entity.add_provenance(source=self.name, confidence=0.8)
                    workspace.add_entity(email_entity)
                    result.add_entity(email_entity)

                    reg_edge = Edge(
                        source_id=entity.id,
                        target_id=email_entity.id,
                        relationship=RelationshipType.REGISTRANT,
                        source_plugin=self.name,
                        confidence=80.0,
                    )
                    workspace.add_edge(reg_edge)
                    result.add_edge(reg_edge)

        except Exception as e:
            result.add_warning(f"WHOIS lookup failed for {entity.value}: {e}")
            entity.metadata["whois_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
