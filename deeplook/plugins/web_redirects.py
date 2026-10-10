from __future__ import annotations

from urllib.parse import urlparse

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class WebRedirectsPlugin(OSINTPlugin):
    name = "web-redirects"
    description = "HTTP redirect chain trace for domains"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.85
    tags = ["passive", "web", "redirects", "http"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        domain = entity.value
        chain: list[dict] = []
        current_url = f"https://{domain}"

        session = requests.Session()
        session.max_redirects = 0

        for _ in range(10):
            hop: dict = {"url": current_url}
            try:
                resp = session.get(
                    current_url,
                    timeout=15,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                    allow_redirects=False,
                )
                hop["status_code"] = resp.status_code
                hop["location"] = resp.headers.get("Location", "")
                hop["final"] = resp.url
                chain.append(hop)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if not location:
                        break
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    current_url = location
                else:
                    break
            except requests.RequestException as e:
                hop["error"] = str(e)
                chain.append(hop)
                break

        entity.metadata["redirect_chain"] = {
            "chain": chain,
            "hop_count": len(chain) - 1,
            "final_url": chain[-1].get("url", "") if chain else "",
        }

        entity.add_provenance(
            source=self.name,
            confidence=0.85,
            raw_data={"hop_count": len(chain) - 1},
        )

        entity.add_tag("redirects-traced")
        workspace.add_entity(entity)
        result.add_entity(entity)

        seen_domains: set[str] = {domain}
        for hop in chain:
            url = hop.get("url", "")
            if not url:
                continue
            parsed = urlparse(url)
            hop_domain = parsed.netloc.lower().rstrip(".")
            if hop_domain and hop_domain not in seen_domains and hop_domain != domain:
                seen_domains.add(hop_domain)
                hop_entity = Entity(type=EntityType.DOMAIN, value=hop_domain, confidence=80.0)
                hop_entity.add_provenance(source=self.name, confidence=0.8)
                workspace.add_entity(hop_entity)
                result.add_entity(hop_entity)

                edge = Edge(
                    source_id=entity.id,
                    target_id=hop_entity.id,
                    relationship=RelationshipType.REDIRECTS_TO,
                    source_plugin=self.name,
                    confidence=0.85,
                    metadata={
                        "status_code": hop.get("status_code"),
                        "location": hop.get("location"),
                    },
                )
                workspace.add_edge(edge)
                result.add_edge(edge)

        result.raw_data = {"redirect_chain": chain}
        return result
