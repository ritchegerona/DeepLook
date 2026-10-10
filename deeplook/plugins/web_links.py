from __future__ import annotations

from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

SOCIAL_DOMAINS = {
    "facebook.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "tiktok.com",
    "reddit.com",
    "pinterest.com",
    "mastodon.social",
    "github.com",
    "gitlab.com",
    "stackoverflow.com",
    "medium.com",
    "t.me",
    "telegram.org",
    "discord.gg",
    "discord.com",
}


@register_plugin
class WebLinks(OSINTPlugin):
    name = "web-links"
    description = "Outbound link extraction and categorization from web pages"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web", "links"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        page_html = None

        for scheme in ["https", "http"]:
            url = f"{scheme}://{entity.value}"
            try:
                resp = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                )
                page_html = resp.text
                break
            except requests.ConnectionError:
                continue
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue
            except Exception:
                continue

        if not page_html:
            result.add_warning(f"Could not fetch page for {entity.value}")
            entity.metadata["links"] = {"internal": 0, "external": 0, "social": []}
            entity.add_provenance(source=self.name, confidence=0.3)
            workspace.add_entity(entity)
            result.add_entity(entity)
            return result

        soup = BeautifulSoup(page_html, "html.parser")
        base_domain = entity.value.lower()

        internal_links: set[str] = set()
        external_links: set[str] = set()
        social_links: list[str] = []

        for a_tag in soup.find_all("a", href=True):
            href = str(a_tag["href"]).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            parsed = urlparse(href)
            link_domain = parsed.netloc.lower()
            if not link_domain:
                internal_links.add(href)
                continue

            link_domain = link_domain.removeprefix("www.")

            is_social = any(sd in link_domain for sd in SOCIAL_DOMAINS)
            if is_social:
                social_links.append(link_domain)

            if link_domain == base_domain or link_domain.endswith(f".{base_domain}"):
                internal_links.add(href)
            else:
                external_links.add(href)

        entity.metadata["links"] = {
            "internal_count": len(internal_links),
            "external_count": len(external_links),
            "social_count": len(social_links),
            "social_links": list(set(social_links)),
        }
        entity.add_provenance(source=self.name, confidence=0.85)
        entity.add_tag("links-extracted")
        workspace.add_entity(entity)
        result.add_entity(entity)

        external_domains: set[str] = set()
        for link in external_links:
            parsed = urlparse(link)
            d = parsed.netloc.lower().removeprefix("www.")
            if d and d != base_domain:
                external_domains.add(d)

        for ext_domain in external_domains:
            ext_entity = Entity(type=EntityType.DOMAIN, value=ext_domain, confidence=80.0)
            ext_entity.add_provenance(source=self.name, confidence=0.8)
            workspace.add_entity(ext_entity)
            result.add_entity(ext_entity)

            edge = Edge(
                source_id=entity.id,
                target_id=ext_entity.id,
                relationship=RelationshipType.LINKS_TO,
                source_plugin=self.name,
                confidence=80.0,
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        return result
