from __future__ import annotations

import socket

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class IPRevDNSPlugin(OSINTPlugin):
    name = "ip-revdns"
    description = "Reverse DNS lookup for IP addresses"
    entity_types = [EntityType.IP]
    requires_key = False
    confidence = 0.9
    tags = ["dns", "reverse-dns", "ip"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            hostname, aliases, _ = socket.gethostbyaddr(entity.value)
            entity.metadata["reverse_dns"] = hostname
            if aliases:
                entity.metadata["dns_aliases"] = aliases

            entity.add_provenance(source="socket.gethostbyaddr", confidence=0.9)
            workspace.add_entity(entity)

            domain_entity = Entity(type=EntityType.DOMAIN, value=hostname)
            domain_entity.add_provenance(source="reverse-dns", confidence=0.9)
            workspace.add_entity(domain_entity)
            result.add_entity(domain_entity)

            edge = Edge(
                source_id=entity.id,
                target_id=domain_entity.id,
                relationship=RelationshipType.REVERSE_DNS,
                source_plugin=self.name,
                confidence=0.9,
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        except (socket.herror, socket.gaierror, OSError) as e:
            result.add_warning(f"Reverse DNS lookup failed for {entity.value}: {e}")

        return result
