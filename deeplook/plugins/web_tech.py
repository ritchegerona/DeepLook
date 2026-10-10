from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

SERVER_SIGNS = {
    "Apache": [r"Apache"],
    "Nginx": [r"nginx"],
    "IIS": [r"Microsoft-IIS"],
    "LiteSpeed": [r"LiteSpeed"],
    "Caddy": [r"Caddy"],
    "OpenResty": [r"openresty"],
}

CMS_SIGNS = {
    "WordPress": [
        r"wp-content/",
        r"wp-includes/",
        r"generator.*WordPress",
        r"/wp-json/",
    ],
    "Drupal": [
        r"Drupal\.settings",
        r"generator.*Drupal",
        r"sites/default/files",
    ],
    "Joomla": [
        r"generator.*Joomla",
        r"/media/jui/",
        r"com_content",
    ],
    "Shopify": [r"cdn\.shopify\.com"],
    "Squarespace": [r"squarespace\.com"],
    "Wix": [r"static\.wixstatic\.com", r"wix\.com"],
    "Ghost": [r"ghost\.io", r"content/themes/"],
}

JS_FRAMEWORKS = {
    "React": [r"react\.min\.js", r"react\.production", r"_reactRootContainer", r"data-reactroot"],
    "Vue.js": [r"vue\.min\.js", r"vue\.runtime", r"__vue__", r"v-cloak"],
    "Angular": [r"angular\.min\.js", r"ng-version", r"ng-app", r"angular\.js"],
    "jQuery": [r"jquery\.min\.js", r"jquery-\d", r"jQuery"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__", r"next\.js"],
    "Nuxt.js": [r"_nuxt/", r"__NUXT__", r"nuxt\.js"],
    "Svelte": [r"svelte\.js", r"svelte\.min\.js"],
}

ANALYTICS = {
    "Google Analytics": [
        r"google-analytics\.com/analytics",
        r"gtag\(",
        r"ga\(",
        r"googletagmanager\.com",
    ],
    "Google Tag Manager": [r"googletagmanager\.com/gtm\.js"],
    "Hotjar": [r"hotjar\.com", r"_hjSettings"],
    "Mixpanel": [r"mixpanel\.com", r"mixpanel\.init"],
    "Segment": [r"segment\.com/analytics", r"analytics\.load"],
    "Plausible": [r"plausible\.io"],
    "Matomo": [r"matomo\.", r"piwik\."],
}

CDN_SIGNS = {
    "Cloudflare": [r"cloudflare", r"cf-ray", r"cf-cache-status"],
    "AWS CloudFront": [r"cloudfront\.net", r"x-amz-cf-id"],
    "Fastly": [r"fastly", r"x-served-by.*fastly"],
    "Akamai": [r"akamai", r"x-akamai"],
    "KeyCDN": [r"keycdn\.com"],
}


def _detect_signs(text: str, patterns: dict[str, list[str]]) -> list[str]:
    matches = []
    for tech, regexes in patterns.items():
        for pat in regexes:
            if re.search(pat, text, re.IGNORECASE):
                matches.append(tech)
                break
    return matches


@register_plugin
class WebTech(OSINTPlugin):
    name = "web-tech"
    description = "Technology stack fingerprinting for web domains"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web", "fingerprinting"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        tech_stack: dict[str, dict[str, list[str]]] = {}

        for scheme in ["https", "http"]:
            url = f"{scheme}://{entity.value}"
            try:
                resp = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                )
                headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                body_text = resp.text
                combined = headers_text + "\n" + body_text

                soup = BeautifulSoup(body_text, "html.parser")
                generator_tag = soup.find("meta", attrs={"name": "generator"})
                generator_content: str = str(generator_tag.get("content", "")) if generator_tag else ""

                detected: dict[str, list[str]] = {}

                server_matches = []
                server_header = resp.headers.get("Server", "")
                if server_header:
                    for name, regexes in SERVER_SIGNS.items():
                        for pat in regexes:
                            if re.search(pat, server_header, re.IGNORECASE):
                                server_matches.append(name)
                                break
                    if server_matches:
                        detected["server"] = server_matches

                powered_by = resp.headers.get("X-Powered-By", "")
                if powered_by:
                    detected.setdefault("server", []).append(powered_by)

                for category, patterns in [
                    ("cms", CMS_SIGNS),
                    ("js_frameworks", JS_FRAMEWORKS),
                    ("analytics", ANALYTICS),
                    ("cdn", CDN_SIGNS),
                ]:
                    found = _detect_signs(combined, patterns)
                    if generator_content:
                        gen_found = _detect_signs(generator_content, patterns)
                        found = list(dict.fromkeys(found + gen_found))
                    if found:
                        detected[category] = found

                if detected:
                    tech_stack[scheme] = detected
                break

            except requests.ConnectionError:
                continue
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue
            except Exception:
                continue

        if not tech_stack:
            entity.add_provenance(source=self.name, confidence=0.3)
            entity.metadata["tech_stack"] = {}
            workspace.add_entity(entity)
            result.add_entity(entity)
            result.add_warning(f"No tech stack detected for {entity.value}")
            return result

        all_techs: dict[str, list[str]] = {}
        for scheme_data in tech_stack.values():
            for category, items in scheme_data.items():
                all_techs.setdefault(category, [])
                all_techs[category] = list(dict.fromkeys(all_techs[category] + items))

        entity.metadata["tech_stack"] = all_techs
        entity.add_provenance(source=self.name, confidence=0.85, raw_data=tech_stack)
        entity.add_tag("tech-fingerprinted")
        workspace.add_entity(entity)
        result.add_entity(entity)

        flat_techs = [t for items in all_techs.values() for t in items]
        for tech_name in flat_techs:
            tech_entity = Entity(type=EntityType.DOMAIN, value=tech_name, confidence=80.0)
            tech_entity.add_provenance(source=self.name, confidence=0.8)
            tech_entity.add_tag("technology")
            workspace.add_entity(tech_entity)
            result.add_entity(tech_entity)

            edge = Edge(
                source_id=entity.id,
                target_id=tech_entity.id,
                relationship=RelationshipType.USES_TECH,
                source_plugin=self.name,
                confidence=80.0,
                metadata={"tech_name": tech_name},
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        return result
