from __future__ import annotations

import xml.etree.ElementTree as ET

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class WebSitemapPlugin(OSINTPlugin):
    name = "web-sitemap"
    description = "Sitemap.xml parser for domain URL enumeration"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.8
    tags = ["passive", "web", "sitemap", "urls"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        domain = entity.value
        urls: list[str] = []

        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            try:
                url = f"https://{domain}{path}"
                resp = requests.get(
                    url,
                    timeout=15,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                    allow_redirects=True,
                )
                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get("Content-Type", "")
                if "xml" not in content_type and "text" not in content_type:
                    continue

                root = ET.fromstring(resp.text)

                ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                loc_elements = root.findall(".//s:loc", ns)
                if not loc_elements:
                    loc_elements = root.findall(".//loc")

                for loc in loc_elements:
                    if loc.text:
                        urls.append(loc.text.strip())

            except ET.ParseError:
                continue
            except requests.RequestException:
                continue

        unique_urls = list(dict.fromkeys(urls))

        entity.metadata["sitemap"] = {
            "urls": unique_urls,
            "url_count": len(unique_urls),
        }

        entity.add_provenance(
            source=self.name,
            confidence=0.8,
            raw_data={"url_count": len(unique_urls)},
        )

        if unique_urls:
            entity.add_tag("sitemap-found")
        else:
            entity.add_tag("no-sitemap")
            result.add_warning(f"No sitemap found for {domain}")

        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
