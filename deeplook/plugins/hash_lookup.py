from __future__ import annotations

import os

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class HashLookupPlugin(OSINTPlugin):
    name = "hash-lookup"
    description = "File hash lookup via VirusTotal (requires API key)"
    entity_types = [EntityType.HASH]
    requires_key = True
    key_env_var = "VT_API_KEY"
    confidence = 0.9
    tags = ["hash", "virustotal", "malware", "file"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            api_key = os.environ.get(self.key_env_var)
            if not api_key:
                result.add_warning(f"Missing {self.key_env_var} for VirusTotal lookup")
                return result

            value = entity.value.lower()
            length = len(value)
            if length == 32:
                hash_type = "MD5"
            elif length == 40:
                hash_type = "SHA1"
            elif length == 64:
                hash_type = "SHA256"
            else:
                result.add_warning(f"Unsupported hash length: {length}")
                return result

            entity.metadata["hash_type"] = hash_type

            url = f"https://www.virustotal.com/api/v3/files/{value}"
            headers = {"x-apikey": api_key}
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            entity.metadata["detection_ratio"] = f"{malicious}/{total}"
            entity.metadata["file_type"] = attrs.get("type_description", "unknown")
            entity.metadata["file_size"] = attrs.get("size", 0)
            entity.metadata["names"] = attrs.get("names", [])[:10]
            entity.metadata["tags"] = attrs.get("tags", [])
            entity.metadata["malicious"] = malicious > 0
            entity.metadata["reputation"] = attrs.get("reputation", 0)
            entity.metadata["last_analysis_date"] = attrs.get("last_analysis_date", "")

            entity.add_provenance(
                source="virustotal",
                confidence=0.9,
                raw_data={"detection_ratio": f"{malicious}/{total}", "type": hash_type},
            )

            if malicious > 0:
                entity.add_tag("malicious")
            else:
                entity.add_tag("clean")

            workspace.add_entity(entity)
            result.add_entity(entity)

            for tag in attrs.get("tags", []):
                if tag not in entity.tags:
                    entity.add_tag(tag)

            result.raw_data = data
        except requests.RequestException as e:
            result.add_warning(f"VirusTotal API request failed: {e}")
            entity.metadata["vt_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)
        except Exception as e:
            result.add_warning(f"Hash lookup failed: {e}")

        return result
