from __future__ import annotations

import os

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"


@register_plugin
class EmailBreach(OSINTPlugin):
    name = "email-breach"
    description = "HaveIBeenPwned breach check for email addresses"
    entity_types = [EntityType.EMAIL]
    requires_key = True
    key_env_var = "HIBP_API_KEY"
    tags = ["passive", "email", "breach"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        try:
            api_key = os.environ.get(self.key_env_var, "")
            if not api_key:
                result.add_warning(f"HIBP API key not found in {self.key_env_var}")
                return result

            email = entity.value.strip().lower()
            url = f"{HIBP_API_BASE}/breachedaccount/{email}"
            headers = {
                "hibp-api-key": api_key,
                "User-Agent": "DeepLook-OSINT/1.0",
            }
            params = {"truncateResponse": "false"}

            resp = requests.get(url, headers=headers, params=params, timeout=10)

            if resp.status_code == 200:
                breaches = resp.json()
                breach_names = [b.get("Name", "") for b in breaches]
                breach_dates = [b.get("BreachDate", "") for b in breaches]
                data_classes = []
                for b in breaches:
                    data_classes.extend(b.get("DataClasses", []))
                data_classes = list(set(data_classes))

                entity.metadata["breached"] = True
                entity.metadata["breach_count"] = len(breaches)
                entity.metadata["breach_names"] = breach_names
                entity.metadata["breach_dates"] = breach_dates
                entity.metadata["data_classes"] = data_classes
                entity.metadata["breaches"] = breaches

                entity.add_tag("breached")
                entity.add_provenance(
                    source=self.name,
                    confidence=0.95,
                    raw_data={"breach_count": len(breaches), "names": breach_names},
                )

                for breach in breaches:
                    breach_name = breach.get("Name", "unknown")
                    breach_entity = Entity(
                        type=EntityType.DOMAIN,
                        value=f"breach:{breach_name}",
                        confidence=95.0,
                    )
                    breach_entity.metadata["breach_name"] = breach_name
                    breach_entity.metadata["breach_date"] = breach.get("BreachDate", "")
                    breach_entity.metadata["data_classes"] = breach.get("DataClasses", [])
                    breach_entity.metadata["pwn_count"] = breach.get("PwnCount", 0)
                    breach_entity.metadata["description"] = breach.get("Description", "")
                    breach_entity.add_provenance(source=self.name, confidence=0.95)
                    breach_entity.add_tag("data-breach")
                    workspace.add_entity(breach_entity)
                    result.add_entity(breach_entity)

                    breach_edge = Edge(
                        source_id=entity.id,
                        target_id=breach_entity.id,
                        relationship=RelationshipType.BREACHED_IN,
                        source_plugin=self.name,
                        confidence=95.0,
                        metadata={"breach_date": breach.get("BreachDate", "")},
                    )
                    workspace.add_edge(breach_edge)
                    result.add_edge(breach_edge)

            elif resp.status_code == 404:
                entity.metadata["breached"] = False
                entity.metadata["breach_count"] = 0
                entity.add_tag("not-breached")
                entity.add_provenance(source=self.name, confidence=0.9, raw_data={"breached": False})

            elif resp.status_code == 401:
                result.add_warning("HIBP API key is invalid or unauthorized")
                entity.metadata["breach_error"] = "unauthorized"
            elif resp.status_code == 429:
                result.add_warning("HIBP API rate limit exceeded, retry later")
                entity.metadata["breach_error"] = "rate_limited"
            else:
                result.add_warning(f"HIBP API returned status {resp.status_code}")
                entity.metadata["breach_error"] = f"http_{resp.status_code}"

            workspace.add_entity(entity)
            result.add_entity(entity)

        except requests.RequestException as e:
            result.add_warning(f"HIBP breach check failed for {entity.value}: {e}")
            entity.metadata["breach_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
