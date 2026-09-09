from __future__ import annotations

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class CrtshPlugin(OSINTPlugin):
    name = "crtsh"
    description = "Certificate transparency subdomain enumeration via crt.sh"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.8
    tags = ["passive", "subdomain", "ct", "certificate"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            url = f"https://crt.sh/?q=%25.{entity.value}&output=json"
            resp = requests.get(url, timeout=30, headers={"User-Agent": "DeepLook OSINT Framework"})
            resp.raise_for_status()

            entries = resp.json()
            seen: set[str] = set()
            subdomains: list[str] = []

            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if not sub or sub.startswith("*"):
                        continue
                    if sub == entity.value:
                        continue
                    if sub not in seen:
                        seen.add(sub)
                        subdomains.append(sub)

            entity.metadata["subdomain_count"] = len(subdomains)
            entity.metadata["crt_sh_entries"] = len(entries)
            entity.add_provenance(
                source=self.name,
                confidence=0.8,
                raw_data={"total_crt_entries": len(entries), "unique_subdomains": len(subdomains)},
            )
            entity.add_tag("subdomain-scanned")
            workspace.add_entity(entity)
            result.add_entity(entity)

            for sub in subdomains:
                sub_entity = Entity(type=EntityType.SUBDOMAIN, value=sub, confidence=75.0)
                sub_entity.add_provenance(source=self.name, confidence=0.75)
                workspace.add_entity(sub_entity)
                result.add_entity(sub_entity)

                edge = Edge(
                    source_id=sub_entity.id,
                    target_id=entity.id,
                    relationship=RelationshipType.SUBDOMAIN_OF,
                    source_plugin=self.name,
                    confidence=75.0,
                )
                workspace.add_edge(edge)
                result.add_edge(edge)

            if not subdomains:
                result.add_warning(f"No subdomains found via crt.sh for {entity.value}")

        except requests.RequestException as e:
            result.add_warning(f"crt.sh request failed for {entity.value}: {e}")
            entity.metadata["crt_sh_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)
        except Exception as e:
            result.add_warning(f"Subdomain enumeration failed for {entity.value}: {e}")

        return result
