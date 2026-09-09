from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class BreachDomainPlugin(OSINTPlugin):
    name = "breach-domain"
    description = "Check domain against threat intelligence feeds (URLhaus, ThreatFox)"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.8
    tags = ["breach", "domain", "threat-intel", "abuse"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            domain = entity.value.strip().lower()

            urlhaus_findings = self._check_urlhaus(domain, entity)
            findings.extend(urlhaus_findings)

            threatfox_findings = self._check_threatfox(domain, entity)
            findings.extend(threatfox_findings)

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="threat-intel-feeds",
                confidence=0.8,
                raw_data={
                    "urlhaus_hits": entity.metadata.get("urlhaus_hits", 0),
                    "threatfox_hits": entity.metadata.get("threatfox_hits", 0),
                },
            )

            if findings and any(f["status"] == "fail" for f in findings):
                entity.add_tag("threat-listed")
            else:
                entity.add_tag("threat-clean")

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {
                "urlhaus": entity.metadata.get("urlhaus_data", {}),
                "threatfox": entity.metadata.get("threatfox_data", {}),
            }

        except Exception as e:
            result.add_warning(f"Breach domain check failed: {e}")

        return result

    def _check_urlhaus(self, domain: str, entity: Entity) -> list[dict]:
        findings: list[dict] = []
        try:
            url = f"https://urlhaus-api.abuse.ch/v1/host/{domain}/"
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            urls_online = data.get("urls_online", 0)
            urls_total = data.get("urls_total", 0)
            blacklists = data.get("blacklists", {})

            entity.metadata["urlhaus_hits"] = urls_online
            entity.metadata["urlhaus_total"] = urls_total
            entity.metadata["urlhaus_blacklists"] = blacklists
            entity.metadata["urlhaus_data"] = data

            if urls_online > 0:
                entity.add_tag("urlhaus-malicious")
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "URLhaus Malicious URLs",
                        "status": "fail",
                        "risk": "critical" if urls_online > 5 else "high",
                        "message": f"Domain has {urls_online} active malicious URL(s) in URLhaus",
                        "recommendation": "Investigate the malicious URLs and consider blocking the domain.",
                    }
                )
            else:
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "URLhaus Malicious URLs",
                        "status": "pass",
                        "risk": "info",
                        "message": "No active malicious URLs found in URLhaus",
                        "recommendation": "",
                    }
                )

            for url_entry in data.get("urls", [])[:5]:
                url_entity = Entity(
                    type=EntityType.DOMAIN,
                    value=f"urlhaus:{url_entry.get('url', '')}",
                    confidence=80.0,
                )
                url_entity.metadata["urlhaus_url"] = url_entry.get("url", "")
                url_entity.metadata["urlhaus_status"] = url_entry.get("url_status", "")
                url_entity.metadata["urlhaus_date_added"] = url_entry.get("date_added", "")
                url_entity.add_provenance(source="urlhaus", confidence=0.8)
                result_obj = PluginResult()
                result_obj.add_entity(url_entity)

        except requests.RequestException:
            findings.append(
                {
                    "category": "Breach Status",
                    "check": "URLhaus Malicious URLs",
                    "status": "info",
                    "risk": "info",
                    "message": "Unable to query URLhaus API",
                    "recommendation": "",
                }
            )

        return findings

    def _check_threatfox(self, domain: str, entity: Entity) -> list[dict]:
        findings: list[dict] = []
        try:
            payload = {
                "query": "search_ioc",
                "search_term": domain,
            }
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

            query_status = data.get("query_status", "")
            ioc_list = data.get("data", []) if query_status == "ok" else []

            entity.metadata["threatfox_hits"] = len(ioc_list)
            entity.metadata["threatfox_data"] = data

            if ioc_list:
                entity.add_tag("threatfox-listed")
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "ThreatFox IOC",
                        "status": "fail",
                        "risk": "high" if len(ioc_list) < 3 else "critical",
                        "message": f"Domain found as IOC in ThreatFox ({len(ioc_list)} record(s))",
                        "recommendation": "Review ThreatFox records and assess threat context.",
                    }
                )
            else:
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "ThreatFox IOC",
                        "status": "pass",
                        "risk": "info",
                        "message": "Domain not found in ThreatFox IOC database",
                        "recommendation": "",
                    }
                )

        except requests.RequestException:
            findings.append(
                {
                    "category": "Breach Status",
                    "check": "ThreatFox IOC",
                    "status": "info",
                    "risk": "info",
                    "message": "Unable to query ThreatFox API",
                    "recommendation": "",
                }
            )

        return findings
