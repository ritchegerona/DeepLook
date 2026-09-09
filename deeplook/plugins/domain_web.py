from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class DomainWeb(OSINTPlugin):
    name = "domain-web"
    description = "HTTP presence check and web fingerprinting for domains"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        urls_to_check = [
            f"https://{entity.value}",
            f"http://{entity.value}",
        ]

        web_data: dict[str, Any] = {}

        for url in urls_to_check:
            scheme = "https" if url.startswith("https") else "http"
            try:
                resp = requests.head(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                )

                redirect_chain = []
                if resp.history:
                    redirect_chain = [r.url for r in resp.history]

                web_data[scheme] = {
                    "status_code": resp.status_code,
                    "server": resp.headers.get("Server", ""),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "final_url": resp.url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": len(redirect_chain),
                    "headers": {k: v for k, v in resp.headers.items()},
                }

            except requests.ConnectionError:
                web_data[scheme] = {"status_code": None, "error": "connection_refused"}
            except requests.Timeout:
                web_data[scheme] = {"status_code": None, "error": "timeout"}
            except requests.RequestException as e:
                web_data[scheme] = {"status_code": None, "error": str(e)}
            except Exception as e:
                web_data[scheme] = {"status_code": None, "error": str(e)}

        entity.metadata["web_presence"] = web_data

        https_data = web_data.get("https", {})
        http_data = web_data.get("http", {})

        if https_data.get("status_code"):
            entity.add_provenance(source=self.name, confidence=0.95, raw_data=web_data)
            entity.add_tag("web-accessible")
        elif http_data.get("status_code"):
            entity.add_provenance(source=self.name, confidence=0.9, raw_data=web_data)
            entity.add_tag("web-accessible")
            entity.add_tag("http-only")
        else:
            entity.add_provenance(source=self.name, confidence=0.5, raw_data=web_data)
            entity.add_tag("no-web-presence")

        server = https_data.get("server") or http_data.get("server")
        if server:
            entity.metadata["server"] = server

        workspace.add_entity(entity)
        result.add_entity(entity)

        for scheme_key in ["https", "http"]:
            data = web_data.get(scheme_key, {})
            final_url = data.get("final_url")
            if final_url and final_url != f"{scheme_key}://{entity.value}":
                parsed = urlparse(final_url)
                redirect_domain = parsed.netloc
                if redirect_domain and redirect_domain != entity.value:
                    redir_entity = Entity(
                        type=EntityType.DOMAIN, value=redirect_domain, confidence=85.0
                    )
                    redir_entity.add_provenance(source=self.name, confidence=0.85)
                    workspace.add_entity(redir_entity)
                    result.add_entity(redir_entity)

                    redir_edge = Edge(
                        source_id=entity.id,
                        target_id=redir_entity.id,
                        relationship=RelationshipType.REDIRECTS_TO,
                        source_plugin=self.name,
                        confidence=85.0,
                        metadata={"scheme": scheme_key, "status": data.get("status_code")},
                    )
                    workspace.add_edge(redir_edge)
                    result.add_edge(redir_edge)

        return result
