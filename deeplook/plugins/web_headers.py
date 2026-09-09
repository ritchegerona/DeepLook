from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-XSS-Protection": "X-XSS-Protection",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
    "X-Permitted-Cross-Domain-Policies": "X-Permitted-Cross-Domain-Policies",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
    "Cross-Origin-Embedder-Policy": "COEP",
}


@register_plugin
class WebHeaders(OSINTPlugin):
    name = "web-headers"
    description = "HTTP response headers analysis with security header auditing"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web", "security"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        for scheme in ["https", "http"]:
            url = f"{scheme}://{entity.value}"
            try:
                resp = requests.head(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                )
                headers = {k: v for k, v in resp.headers.items()}
                break
            except requests.ConnectionError:
                continue
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue
            except Exception:
                continue
        else:
            result.add_warning(f"Could not fetch headers for {entity.value}")
            entity.metadata["headers"] = {}
            entity.metadata["security_headers"] = {}
            entity.metadata["missing_security_headers"] = list(SECURITY_HEADERS.values())
            entity.add_provenance(source=self.name, confidence=0.3)
            workspace.add_entity(entity)
            result.add_entity(entity)
            return result

        security_found: dict[str, str] = {}
        missing: list[str] = []

        for header_name, label in SECURITY_HEADERS.items():
            if header_name in headers:
                security_found[label] = headers[header_name]
            else:
                missing.append(label)

        entity.metadata["headers"] = headers
        entity.metadata["security_headers"] = security_found
        entity.metadata["missing_security_headers"] = missing

        total = len(SECURITY_HEADERS)
        found_count = total - len(missing)
        score = round(found_count / total * 100, 1) if total > 0 else 0
        entity.metadata["security_score"] = score

        entity.add_provenance(source=self.name, confidence=0.95, raw_data=headers)
        entity.add_tag("headers-analyzed")
        if missing:
            entity.add_tag("missing-security-headers")
        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
