from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/adminer",
    "/cpanel",
    "/webmail",
    "/manager",
    "/console",
    "/manager/html",
]

DEBUG_PATHS = [
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/trace",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/server-status",
    "/server-info",
    "/_profiler",
    "/_wdt",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
]

SENSITIVE_PATHS = [
    "/.env",
    "/config",
    "/backup",
    "/db",
    "/database",
    "/sql",
    "/phpmyadmin",
    "/elmah.axd",
    "/trace.axd",
    "/jmx-console",
    "/web-console",
    "/solr/admin",
    "/jenkins",
]


@register_plugin
class ExposedServicesPlugin(OSINTPlugin):
    name = "exposed-services"
    description = "Detect exposed admin panels, debug endpoints, and sensitive services"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.8
    tags = ["admin", "debug", "exposure", "services"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            domain = entity.value.strip().lower()
            base_url = f"https://{domain}"

            all_paths = (
                [(p, "Admin Panel") for p in ADMIN_PATHS]
                + [(p, "Debug Endpoint") for p in DEBUG_PATHS]
                + [(p, "Sensitive Service") for p in SENSITIVE_PATHS]
            )

            found_admin = []
            found_debug = []
            found_sensitive = []

            for path, category in all_paths:
                try:
                    url = f"{base_url}{path}"
                    resp = requests.head(
                        url,
                        timeout=10,
                        allow_redirects=False,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; DeepLook/1.0)"},
                        verify=False,
                    )
                    if resp.status_code in (200, 301, 302, 401, 403):
                        entry = {"path": path, "status": resp.status_code}
                        if category == "Admin Panel":
                            found_admin.append(entry)
                        elif category == "Debug Endpoint":
                            found_debug.append(entry)
                        else:
                            found_sensitive.append(entry)
                except requests.RequestException:
                    continue

            if found_admin:
                for entry in found_admin:
                    findings.append(
                        {
                            "category": "Exposure Risk",
                            "check": "Admin Panel Exposed",
                            "status": "fail",
                            "risk": "high",
                            "message": (
                                f"Admin panel accessible at {entry['path']} "
                                f"(HTTP {entry['status']})"
                            ),
                            "recommendation": (
                                "Restrict access to admin panels via IP whitelist, "
                                "VPN, or authentication."
                            ),
                        }
                    )
                    entity.add_tag("admin-exposed")

            if found_debug:
                for entry in found_debug:
                    findings.append(
                        {
                            "category": "Exposure Risk",
                            "check": "Debug Endpoint Exposed",
                            "status": "fail",
                            "risk": "high",
                            "message": (
                                f"Debug endpoint accessible at {entry['path']} "
                                f"(HTTP {entry['status']})"
                            ),
                            "recommendation": (
                                "Disable debug endpoints in production or restrict access."
                            ),
                        }
                    )
                    entity.add_tag("debug-exposed")

            if found_sensitive:
                for entry in found_sensitive:
                    findings.append(
                        {
                            "category": "Exposure Risk",
                            "check": "Sensitive Service Exposed",
                            "status": "fail",
                            "risk": "high",
                            "message": (
                                f"Sensitive service at {entry['path']} (HTTP {entry['status']})"
                            ),
                            "recommendation": "Restrict or remove exposed sensitive services.",
                        }
                    )
                    entity.add_tag("sensitive-exposed")

            if not found_admin and not found_debug and not found_sensitive:
                findings.append(
                    {
                        "category": "Exposure Risk",
                        "check": "Exposed Services",
                        "status": "pass",
                        "risk": "info",
                        "message": "No exposed admin panels, debug endpoints, or sensitive services detected",
                        "recommendation": "",
                    }
                )

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="exposed-services",
                confidence=0.8,
                raw_data={
                    "admin_found": found_admin,
                    "debug_found": found_debug,
                    "sensitive_found": found_sensitive,
                },
            )

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {
                "admin": found_admin,
                "debug": found_debug,
                "sensitive": found_sensitive,
            }

        except Exception as e:
            result.add_warning(f"Exposed services check failed: {e}")

        return result
