from __future__ import annotations

import random

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

PLATFORM_URLS = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Twitter": "https://x.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "Medium": "https://medium.com/@{}",
    "Keybase": "https://keybase.io/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0.0.0",
]


@register_plugin
class UsernameSocial(OSINTPlugin):
    name = "username-social"
    description = "Cross-platform username enumeration across social media and developer platforms"
    entity_types = [EntityType.USERNAME]
    tags = ["passive", "social", "username"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        try:
            username = entity.value
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            found_platforms: list[str] = []

            for platform, url_template in PLATFORM_URLS.items():
                try:
                    url = url_template.format(username)
                    resp = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
                    status = resp.status_code

                    if status in (200, 302):
                        found_platforms.append(platform)
                        domain_val = url.split("//")[1].split("/")[0].lower()

                        domain_entity = Entity(type=EntityType.DOMAIN, value=domain_val, confidence=90.0)
                        domain_entity.add_provenance(
                            source=self.name,
                            confidence=0.9,
                            raw_data={"platform": platform, "url": url, "status_code": status},
                        )
                        domain_entity.add_tag("social-profile")
                        workspace.add_entity(domain_entity)
                        result.add_entity(domain_entity)

                        profile_edge = Edge(
                            source_id=entity.id,
                            target_id=domain_entity.id,
                            relationship=RelationshipType.PROFILE_ON,
                            source_plugin=self.name,
                            confidence=90.0,
                            metadata={"platform": platform, "url": url},
                        )
                        workspace.add_edge(profile_edge)
                        result.add_edge(profile_edge)
                except requests.RequestException:
                    continue

            entity.metadata["found_platforms"] = found_platforms
            entity.metadata["platforms_checked"] = len(PLATFORM_URLS)
            entity.metadata["platforms_found"] = len(found_platforms)
            entity.add_provenance(source=self.name, confidence=0.85, raw_data={"found": found_platforms})
            workspace.add_entity(entity)
            result.add_entity(entity)

        except Exception as e:
            result.add_warning(f"Username social enumeration failed for {entity.value}: {e}")
            entity.metadata["social_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
