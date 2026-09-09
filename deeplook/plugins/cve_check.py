from __future__ import annotations

import re

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

KNOWN_VULNERABLE = {
    "Apache": {"min_safe": "2.4.49", "cpe": "cpe:2.3:a:apache:http_server"},
    "nginx": {"min_safe": "1.21.1", "cpe": "cpe:2.3:a:nginx:nginx"},
    "PHP": {"min_safe": "7.4.0", "cpe": "cpe:2.3:a:php:php"},
    "IIS": {"min_safe": "10.0", "cpe": "cpe:2.3:a:microsoft:internet_information_services"},
    "OpenSSL": {"min_safe": "1.1.1", "cpe": "cpe:2.3:a:openssl:openssl"},
    "LiteSpeed": {"min_safe": "5.4.12", "cpe": "cpe:2.3:a:litespeed:openlitespeed"},
    "lighttpd": {"min_safe": "1.4.58", "cpe": "cpe:2.3:a:lighttpd:lighttpd"},
}


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.split(r"[^0-9]+", v)
    return tuple(int(p) for p in parts if p)


@register_plugin
class CveCheckPlugin(OSINTPlugin):
    name = "cve-check"
    description = "Check software versions against known CVE database"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.7
    tags = ["cve", "vulnerability", "version", "exposure"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            domain = entity.value.strip().lower()
            url = f"https://{domain}"

            resp = requests.get(
                url,
                timeout=15,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; DeepLook/1.0)",
                },
            )

            server = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")

            entity.metadata["server_header"] = server
            entity.metadata["x_powered_by"] = powered_by

            detected = []
            if server:
                for name in KNOWN_VULNERABLE:
                    if name.lower() in server.lower():
                        version_match = re.search(
                            rf"{re.escape(name)}[/\s]+(\d+[\d.]*)",
                            server,
                            re.IGNORECASE,
                        )
                        ver = version_match.group(1) if version_match else "unknown"
                        detected.append((name, ver, server))
            if powered_by:
                for name in KNOWN_VULNERABLE:
                    if name.lower() in powered_by.lower():
                        version_match = re.search(
                            rf"{re.escape(name)}[/\s]+(\d+[\d.]*)",
                            powered_by,
                            re.IGNORECASE,
                        )
                        ver = version_match.group(1) if version_match else "unknown"
                        detected.append((name, ver, powered_by))

            if detected:
                for name, ver, header_val in detected:
                    safe_ver = KNOWN_VULNERABLE[name]["min_safe"]
                    if ver != "unknown" and _version_tuple(ver) < _version_tuple(safe_ver):
                        findings.append(
                            {
                                "category": "Exposure Risk",
                                "check": f"Vulnerable Software: {name}",
                                "status": "fail",
                                "risk": "high",
                                "message": f"{name} {ver} detected (safe: {safe_ver}+)",
                                "recommendation": f"Upgrade {name} to {safe_ver} or later.",
                            }
                        )
                        entity.add_tag(f"vulnerable-{name.lower()}")
                    else:
                        findings.append(
                            {
                                "category": "Exposure Risk",
                                "check": f"Software Version: {name}",
                                "status": "pass",
                                "risk": "info",
                                "message": f"{name} {ver} appears up to date",
                                "recommendation": "",
                            }
                        )
            else:
                findings.append(
                    {
                        "category": "Exposure Risk",
                        "check": "Software Version Disclosure",
                        "status": "info",
                        "risk": "info",
                        "message": "No identifiable software versions in HTTP headers",
                        "recommendation": "",
                    }
                )

            entity.metadata["detected_software"] = [
                {"name": n, "version": v, "header": h} for n, v, h in detected
            ]

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="cve-check",
                confidence=0.7,
                raw_data={
                    "server": server,
                    "x_powered_by": powered_by,
                    "detected_software": entity.metadata["detected_software"],
                },
            )

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {
                "server": server,
                "x_powered_by": powered_by,
                "detected": entity.metadata["detected_software"],
            }

        except requests.RequestException as e:
            result.add_warning(f"CVE check failed: {e}")
        except Exception as e:
            result.add_warning(f"CVE check failed: {e}")

        return result
