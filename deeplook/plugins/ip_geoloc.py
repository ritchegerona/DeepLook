from __future__ import annotations

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class IPGeolocPlugin(OSINTPlugin):
    name = "ip-geoloc"
    description = "IP geolocation via ip-api.com (free, no key required)"
    entity_types = [EntityType.IP]
    requires_key = False
    confidence = 0.7
    tags = ["geolocation", "ip", "network"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            url = f"http://ip-api.com/json/{entity.value}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") == "fail":
                result.add_warning(f"ip-api query failed: {data.get('message', 'unknown error')}")
                return result

            entity.metadata["country"] = data.get("country", "")
            entity.metadata["country_code"] = data.get("countryCode", "")
            entity.metadata["region"] = data.get("regionName", "")
            entity.metadata["city"] = data.get("city", "")
            entity.metadata["zip"] = data.get("zip", "")
            entity.metadata["latitude"] = data.get("lat", 0.0)
            entity.metadata["longitude"] = data.get("lon", 0.0)
            entity.metadata["timezone"] = data.get("timezone", "")
            entity.metadata["isp"] = data.get("isp", "")
            entity.metadata["org"] = data.get("org", "")
            entity.metadata["as"] = data.get("as", "")
            entity.metadata["asname"] = data.get("asname", "")
            entity.metadata["reverse_dns"] = data.get("reverse", "")
            entity.metadata["mobile"] = data.get("mobile", False)
            entity.metadata["proxy"] = data.get("proxy", False)
            entity.metadata["hosting"] = data.get("hosting", False)

            entity.add_provenance(source="ip-api.com", confidence=0.7, raw_data=data)
            workspace.add_entity(entity)

            org_name = data.get("org", "") or data.get("isp", "")
            if org_name:
                org_entity = Entity(type=EntityType.ORG, value=org_name)
                org_entity.add_provenance(source="ip-api.com", confidence=0.7)
                workspace.add_entity(org_entity)
                result.add_entity(org_entity)

                edge = Edge(
                    source_id=entity.id,
                    target_id=org_entity.id,
                    relationship=RelationshipType.ASSOCIATED_WITH,
                    source_plugin=self.name,
                    confidence=0.7,
                )
                workspace.add_edge(edge)
                result.add_edge(edge)

            result.raw_data = data
        except requests.RequestException as e:
            result.add_warning(f"Failed to query ip-api.com: {e}")

        return result
