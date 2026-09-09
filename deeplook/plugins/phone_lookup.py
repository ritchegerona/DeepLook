from __future__ import annotations

import os

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

NUMVERIFY_API = "http://apilayer.net/api/validate"


@register_plugin
class PhoneLookup(OSINTPlugin):
    name = "phone-lookup"
    description = "Phone number validation and carrier lookup via NumVerify"
    entity_types = [EntityType.PHONE]
    requires_key = True
    key_env_var = "NUMVERIFY_API_KEY"
    tags = ["passive", "phone", "validation"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        try:
            api_key = os.environ.get(self.key_env_var, "")
            if not api_key:
                result.add_warning(f"NumVerify API key not found in {self.key_env_var}")
                return result

            phone = entity.value.strip()
            params = {
                "access_key": api_key,
                "number": phone,
                "country_code": "",
            }

            resp = requests.get(NUMVERIFY_API, params=params, timeout=10)

            if resp.status_code == 200:
                data = resp.json()

                if data.get("valid") is True:
                    entity.metadata["valid"] = True
                    entity.metadata["local_format"] = data.get("local_format", "")
                    entity.metadata["international_format"] = data.get("international_format", "")
                    entity.metadata["country_prefix"] = data.get("country_prefix", "")
                    entity.metadata["country_code"] = data.get("country_code", "")
                    entity.metadata["country_name"] = data.get("country_name", "")
                    entity.metadata["location"] = data.get("location", "")
                    entity.metadata["carrier"] = data.get("carrier", "")
                    entity.metadata["line_type"] = data.get("line_type", "")

                    entity.add_tag("valid-phone")
                    if data.get("line_type") == "mobile":
                        entity.add_tag("mobile-phone")
                    elif data.get("line_type") == "landline":
                        entity.add_tag("landline-phone")

                    entity.add_provenance(
                        source=self.name,
                        confidence=0.9,
                        raw_data=data,
                    )

                    if data.get("country_code"):
                        country_entity = Entity(
                            type=EntityType.DOMAIN,
                            value=data["country_code"].lower(),
                            confidence=85.0,
                        )
                        country_entity.metadata["country_name"] = data.get("country_name", "")
                        country_entity.add_provenance(source=self.name, confidence=0.85)
                        country_entity.add_tag("country-code")
                        workspace.add_entity(country_entity)
                        result.add_entity(country_entity)

                        country_edge = Edge(
                            source_id=entity.id,
                            target_id=country_entity.id,
                            relationship=RelationshipType.ASSOCIATED_WITH,
                            source_plugin=self.name,
                            confidence=85.0,
                            metadata={"relation": "country_of_origin"},
                        )
                        workspace.add_edge(country_edge)
                        result.add_edge(country_edge)

                elif data.get("valid") is False:
                    entity.metadata["valid"] = False
                    entity.metadata["error"] = data.get("error", {}).get("info", "Invalid number")
                    entity.add_tag("invalid-phone")
                    entity.add_provenance(source=self.name, confidence=0.8, raw_data=data)

            elif resp.status_code == 101:
                result.add_warning("NumVerify API key is invalid or missing")
                entity.metadata["lookup_error"] = "invalid_key"
            elif resp.status_code == 104:
                result.add_warning("NumVerify API usage limit reached")
                entity.metadata["lookup_error"] = "usage_limit"
            else:
                result.add_warning(f"NumVerify API returned status {resp.status_code}")
                entity.metadata["lookup_error"] = f"http_{resp.status_code}"

            workspace.add_entity(entity)
            result.add_entity(entity)

        except requests.RequestException as e:
            result.add_warning(f"Phone lookup failed for {entity.value}: {e}")
            entity.metadata["lookup_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
