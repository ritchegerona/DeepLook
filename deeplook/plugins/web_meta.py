from __future__ import annotations

import requests
from bs4 import BeautifulSoup

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class WebMetaPlugin(OSINTPlugin):
    name = "web-meta"
    description = "HTML metadata extraction (title, OG, Twitter Cards, favicon)"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.85
    tags = ["passive", "web", "metadata", "html"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        domain = entity.value

        try:
            url = f"https://{domain}"
            resp = requests.get(
                url,
                timeout=15,
                headers={"User-Agent": "DeepLook OSINT Framework"},
                allow_redirects=True,
            )
            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "html.parser")

            title = ""
            title_tag = soup.find("title")
            if title_tag and title_tag.string:
                title = title_tag.string.strip()

            meta_desc = ""
            desc_tag = soup.find("meta", attrs={"name": "description"})
            if desc_tag:
                meta_desc = desc_tag.get("content", "")

            og: dict[str, str] = {}
            for attr in ("og:title", "og:description", "og:image", "og:type", "og:url"):
                tag = soup.find("meta", attrs={"property": attr})
                if tag:
                    og[attr] = tag.get("content", "")

            twitter: dict[str, str] = {}
            for attr in ("twitter:card", "twitter:title", "twitter:description", "twitter:image"):
                tag = soup.find("meta", attrs={"name": attr})
                if tag:
                    twitter[attr] = tag.get("content", "")

            favicon = ""
            link_tag = soup.find("link", attrs={"rel": "icon"}) or soup.find(
                "link", attrs={"rel": "shortcut icon"}
            )
            if link_tag:
                favicon = link_tag.get("href", "")

            entity.metadata["meta"] = {
                "title": title,
                "meta_description": meta_desc,
                "og": og,
                "twitter": twitter,
                "favicon": favicon,
            }

            entity.add_provenance(
                source=self.name,
                confidence=0.85,
                raw_data={"title": title, "og_tags": len(og), "twitter_tags": len(twitter)},
            )

            if title:
                entity.add_tag("meta-title-found")
            workspace.add_entity(entity)
            result.add_entity(entity)

        except requests.RequestException as e:
            entity.metadata["meta"] = {"error": str(e)}
            result.add_warning(f"Failed to fetch page for {domain}: {e}")
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
