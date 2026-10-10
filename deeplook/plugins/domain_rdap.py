"""Domain registration data via RDAP (free, no API key required)."""

from __future__ import annotations

from typing import Any

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

_RDAP_URL = "https://rdap.org/domain/{domain}"


@register_plugin
class DomainRDAPPlugin(OSINTPlugin):
    name = "domain-rdap"
    description = "Domain registration data via RDAP (free, no key required)"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.85
    tags = ["whois", "rdap", "domain", "registration"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            resp = requests.get(
                _RDAP_URL.format(domain=entity.value),
                timeout=15,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code == 404:
                result.add_warning(f"No RDAP record for {entity.value}")
                return result
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            result.add_warning(f"Failed to query RDAP: {e}")
            return result
        except ValueError as e:
            result.add_warning(f"Invalid RDAP response: {e}")
            return result

        registrar = self._registrar(data)
        created = self._event(data, "registration")
        expires = self._event(data, "expiration")
        updated = self._event(data, "last changed")
        nameservers = [ns["ldhName"].lower() for ns in data.get("nameservers", []) if ns.get("ldhName")]
        statuses = data.get("status", [])

        meta = entity.metadata
        if registrar:
            meta.setdefault("registrar", registrar)
        if created:
            meta.setdefault("creation_date", created)
        if expires:
            meta.setdefault("expiration_date", expires)
        if nameservers:
            meta.setdefault("name_servers", nameservers)
        meta["rdap_registrar"] = registrar
        meta["rdap_created"] = created
        meta["rdap_expires"] = expires
        meta["rdap_updated"] = updated
        meta["rdap_status"] = statuses

        entity.add_provenance(source=self.name, confidence=self.confidence, raw_data={"handle": data.get("handle", "")})
        workspace.add_entity(entity)

        for ns in nameservers[:20]:
            ns_entity = Entity(type=EntityType.DOMAIN, value=ns)
            ns_entity.add_provenance(source=self.name, confidence=0.8)
            workspace.add_entity(ns_entity)
            edge = Edge(
                source_id=entity.id,
                target_id=ns_entity.id,
                relationship=RelationshipType.NS_RECORD,
                source_plugin=self.name,
                confidence=0.8,
            )
            workspace.add_edge(edge)
            result.add_entity(ns_entity)
            result.add_edge(edge)

        if registrar:
            registrar_entity = Entity(type=EntityType.ORG, value=registrar)
            registrar_entity.add_provenance(source=self.name, confidence=0.8)
            workspace.add_entity(registrar_entity)
            edge = Edge(
                source_id=entity.id,
                target_id=registrar_entity.id,
                relationship=RelationshipType.REGISTRANT,
                source_plugin=self.name,
                confidence=0.8,
            )
            workspace.add_edge(edge)
            result.add_entity(registrar_entity)
            result.add_edge(edge)

        result.metadata["registrar"] = registrar
        result.metadata["status_count"] = len(statuses)
        result.raw_data = data
        return result

    @staticmethod
    def _event(data: dict[str, Any], action: str) -> str:
        for event in data.get("events", []):
            if event.get("eventAction") == action:
                return event.get("eventDate", "")
        return ""

    @staticmethod
    def _registrar(data: dict[str, Any]) -> str:
        for ent in data.get("entities", []):
            if "registrar" not in ent.get("roles", []):
                continue
            vcard = ent.get("vcardArray", [])
            if len(vcard) == 2:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        return item[3]
            return ent.get("handle", "")
        return ""
