from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@register_plugin
class WebEmails(OSINTPlugin):
    name = "web-emails"
    description = "Email address extraction from web pages"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web", "email"]

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
            entity.metadata["emails"] = []
            entity.add_provenance(source=self.name, confidence=0.3)
            workspace.add_entity(entity)
            result.add_entity(entity)
            return result

        soup = BeautifulSoup(page_html, "html.parser")
        emails: set[str] = set()

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.lower().startswith("mailto:"):
                email_part = href[7:].split("?")[0].strip()
                if EMAIL_RE.match(email_part):
                    emails.add(email_part.lower())

        text_content = soup.get_text(separator=" ")
        for match in EMAIL_RE.finditer(text_content):
            email = match.group(0).lower()
            if EMAIL_RE.match(email):
                emails.add(email)

        email_list = sorted(emails)
        entity.metadata["emails"] = email_list
        entity.metadata["email_count"] = len(email_list)
        entity.add_provenance(source=self.name, confidence=0.85, raw_data={"emails": email_list})
        entity.add_tag("emails-extracted")
        workspace.add_entity(entity)
        result.add_entity(entity)

        for email_value in email_list:
            email_entity = Entity(type=EntityType.EMAIL, value=email_value, confidence=80.0)
            email_entity.add_provenance(source=self.name, confidence=0.8)
            workspace.add_entity(email_entity)
            result.add_entity(email_entity)

            edge = Edge(
                source_id=entity.id,
                target_id=email_entity.id,
                relationship=RelationshipType.CONTACT_EMAIL,
                source_plugin=self.name,
                confidence=80.0,
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        return result
