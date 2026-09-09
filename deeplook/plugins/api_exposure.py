from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

API_PATHS = [
    {
        "path": "/swagger",
        "name": "Swagger UI",
        "risk": "medium",
        "recommendation": "Restrict access to API documentation in production.",
    },
    {
        "path": "/swagger-ui",
        "name": "Swagger UI",
        "risk": "medium",
        "recommendation": "Restrict access to API documentation in production.",
    },
    {
        "path": "/swagger-ui.html",
        "name": "Swagger UI HTML",
        "risk": "medium",
        "recommendation": "Restrict access to API documentation in production.",
    },
    {
        "path": "/api-docs",
        "name": "API Documentation",
        "risk": "medium",
        "recommendation": "Restrict access to API documentation in production.",
    },
    {
        "path": "/graphql",
        "name": "GraphQL Endpoint",
        "risk": "medium",
        "recommendation": "Enable authentication and query depth limiting on GraphQL.",
    },
    {"path": "/api/v1", "name": "API v1", "risk": "info", "recommendation": ""},
    {"path": "/api/v2", "name": "API v2", "risk": "info", "recommendation": ""},
    {
        "path": "/api/internal",
        "name": "Internal API",
        "risk": "high",
        "recommendation": "Remove or restrict access to internal API endpoints.",
    },
    {
        "path": "/api/admin",
        "name": "Admin API",
        "risk": "high",
        "recommendation": "Restrict admin API access to authorized clients only.",
    },
    {
        "path": "/.well-known/openapi.json",
        "name": "OpenAPI Spec",
        "risk": "medium",
        "recommendation": "Restrict access to OpenAPI specification in production.",
    },
    {
        "path": "/openapi.json",
        "name": "OpenAPI Spec",
        "risk": "medium",
        "recommendation": "Restrict access to OpenAPI specification in production.",
    },
    {
        "path": "/api/swagger.json",
        "name": "Swagger JSON",
        "risk": "medium",
        "recommendation": "Restrict access to Swagger spec in production.",
    },
    {
        "path": "/_api",
        "name": "Underscore API",
        "risk": "medium",
        "recommendation": "Review and restrict access to API endpoints.",
    },
    {"path": "/api/", "name": "API Root", "risk": "info", "recommendation": ""},
]


@register_plugin
class ApiExposurePlugin(OSINTPlugin):
    name = "api-exposure"
    description = "Detect exposed API endpoints and documentation"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.75
    tags = ["api", "exposure", "swagger", "graphql"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            domain = entity.value.strip().lower()
            base_url = f"https://{domain}"

            exposed_apis: list[dict] = []

            for check in API_PATHS:
                try:
                    url = f"{base_url}{check['path']}"
                    resp = requests.get(
                        url,
                        timeout=10,
                        allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; DeepLook/1.0)"},
                        verify=False,
                    )
                    content_type = resp.headers.get("Content-Type", "")
                    is_json = "json" in content_type
                    is_api = resp.status_code == 200 and (
                        is_json
                        or "swagger" in resp.text[:500].lower()
                        or "openapi" in resp.text[:500].lower()
                        or "graphql" in resp.text[:500].lower()
                    )

                    if is_api:
                        exposed_apis.append(
                            {
                                "path": check["path"],
                                "name": check["name"],
                                "risk": check["risk"],
                                "status_code": resp.status_code,
                                "content_type": content_type,
                                "recommendation": check["recommendation"],
                            }
                        )
                except requests.RequestException:
                    continue

            if exposed_apis:
                for api in exposed_apis:
                    if api["risk"] == "high":
                        status = "fail"
                    elif api["risk"] == "medium":
                        status = "warn"
                    else:
                        status = "info"

                    findings.append(
                        {
                            "category": "Exposure Risk",
                            "check": f"API Exposure: {api['name']}",
                            "status": status,
                            "risk": api["risk"],
                            "message": (
                                f"{api['name']} accessible at {api['path']} "
                                f"(HTTP {api['status_code']}, {api['content_type']})"
                            ),
                            "recommendation": api["recommendation"],
                        }
                    )
                    entity.add_tag("api-exposed")
            else:
                findings.append(
                    {
                        "category": "Exposure Risk",
                        "check": "API Exposure",
                        "status": "pass",
                        "risk": "info",
                        "message": "No exposed API endpoints or documentation detected",
                        "recommendation": "",
                    }
                )

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="api-exposure",
                confidence=0.75,
                raw_data={"exposed_apis": exposed_apis},
            )

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {"exposed_apis": exposed_apis}

        except Exception as e:
            result.add_warning(f"API exposure check failed: {e}")

        return result
