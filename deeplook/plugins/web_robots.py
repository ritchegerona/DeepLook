from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class WebRobotsPlugin(OSINTPlugin):
    name = "web-robots"
    description = "Robots.txt parser for crawl policy analysis"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.9
    tags = ["passive", "web", "robots", "crawl"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        domain = entity.value

        try:
            url = f"https://{domain}/robots.txt"
            resp = requests.get(
                url,
                timeout=15,
                headers={"User-Agent": "DeepLook OSINT Framework"},
                allow_redirects=True,
            )
            resp.raise_for_status()

            disallowed: list[str] = []
            allowed: list[str] = []
            sitemaps: list[str] = []
            crawl_delay: str | None = None

            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                lower = line.lower()
                if lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif lower.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        allowed.append(path)
                elif lower.startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm:
                        sitemaps.append(sm)
                elif lower.startswith("crawl-delay:"):
                    delay = line.split(":", 1)[1].strip()
                    if delay:
                        crawl_delay = delay

            entity.metadata["robots"] = {
                "disallowed": disallowed,
                "allowed": allowed,
                "sitemaps": sitemaps,
                "crawl_delay": crawl_delay,
                "raw": resp.text,
            }

            entity.add_provenance(
                source=self.name,
                confidence=0.9,
                raw_data={
                    "disallowed_count": len(disallowed),
                    "allowed_count": len(allowed),
                    "sitemaps_count": len(sitemaps),
                },
            )

            entity.add_tag("robots-parsed")
            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = resp.text

        except requests.RequestException as e:
            entity.metadata["robots"] = {"error": str(e)}
            entity.add_tag("no-robots")
            result.add_warning(f"Failed to fetch robots.txt for {domain}: {e}")
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
