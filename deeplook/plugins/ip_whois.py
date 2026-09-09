from __future__ import annotations

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class IPWhoisPlugin(OSINTPlugin):
    name = "ip-whois"
    description = "IP WHOIS/RDAP lookup for network registration data"
    entity_types = [EntityType.IP]
    requires_key = False
    confidence = 0.85
    tags = ["whois", "rdap", "registration", "ip"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            url = f"https://rdap.org/ip/{entity.value}"
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            entity.metadata["network_name"] = data.get("name", "")
            entity.metadata["rdap_handle"] = data.get("handle", "")

            start = data.get("startAddress", "")
            end = data.get("endAddress", "")
            if start and end:
                entity.metadata["network_range"] = f"{start} - {end}"

            country = ""
            for entity_obj in data.get("entities", []):
                if "registrant" in entity_obj.get("roles", []):
                    for vc in entity_obj.get("vcardArray", [None, []])[1]:
                        if vc[0] == "adr":
                            country = vc[3] if len(vc) > 3 else ""
            if not country:
                country = data.get("country", "")
            entity.metadata["country"] = country

            org_name = ""
            for entity_obj in data.get("entities", []):
                roles = entity_obj.get("roles", [])
                if "registrant" in roles or "administrative" in roles:
                    for vc in entity_obj.get("vcardArray", [None, []])[1]:
                        if vc[0] == "fn":
                            org_name = vc[3] if len(vc) > 3 else vc[1]
                            break
                    if org_name:
                        break

            entity.add_provenance(source="rdap.org", confidence=0.85, raw_data=data)
            workspace.add_entity(entity)

            if org_name:
                org_entity = Entity(type=EntityType.ORG, value=org_name)
                org_entity.metadata["country"] = country
                org_entity.add_provenance(source="rdap.org", confidence=0.85)
                workspace.add_entity(org_entity)
                result.add_entity(org_entity)

                edge = Edge(
                    source_id=entity.id,
                    target_id=org_entity.id,
                    relationship=RelationshipType.OWNED_BY,
                    source_plugin=self.name,
                    confidence=0.85,
                )
                workspace.add_edge(edge)
                result.add_edge(edge)

            result.raw_data = data
        except requests.RequestException as e:
            result.add_warning(f"Failed to query RDAP: {e}")

        return result
