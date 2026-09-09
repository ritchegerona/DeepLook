from __future__ import annotations

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class IPPortsPlugin(OSINTPlugin):
    name = "ip-ports"
    description = "Port scan via Shodan InternetDB (free, no key required)"
    entity_types = [EntityType.IP]
    requires_key = False
    confidence = 0.8
    tags = ["ports", "shodan", "network", "scan"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            url = f"https://internetdb.shodan.io/{entity.value}"
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            entity.metadata["ports"] = data.get("ports", [])
            entity.metadata["hostnames"] = data.get("hostnames", [])
            entity.metadata["vulns"] = data.get("vulns", [])
            entity.metadata["tags"] = data.get("tags", [])
            entity.metadata["cpes"] = data.get("cpes", [])

            entity.add_provenance(source="shodan-internetdb", confidence=0.8, raw_data=data)
            workspace.add_entity(entity)

            for hostname in data.get("hostnames", []):
                domain_entity = Entity(type=EntityType.DOMAIN, value=hostname)
                domain_entity.add_provenance(source="shodan-internetdb", confidence=0.8)
                workspace.add_entity(domain_entity)
                result.add_entity(domain_entity)

                edge = Edge(
                    source_id=entity.id,
                    target_id=domain_entity.id,
                    relationship=RelationshipType.HOSTED_ON,
                    source_plugin=self.name,
                    confidence=0.8,
                )
                workspace.add_edge(edge)
                result.add_edge(edge)

            result.raw_data = data
        except requests.RequestException as e:
            result.add_warning(f"Failed to query Shodan InternetDB: {e}")

        return result
