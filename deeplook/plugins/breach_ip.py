from __future__ import annotations

import os

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class BreachIPPlugin(OSINTPlugin):
    name = "breach-ip"
    description = "Check IP reputation and abuse reports (AbuseIPDB, ip-api)"
    entity_types = [EntityType.IP]
    requires_key = False
    key_env_var = "ABUSEIPDB_API_KEY"
    confidence = 0.8
    tags = ["breach", "ip", "abuse", "reputation"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            ip = entity.value.strip()
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")

            if api_key:
                abuse_findings = self._check_abuseipdb(ip, api_key, entity)
                findings.extend(abuse_findings)
            else:
                fallback_findings = self._check_ipapi(ip, entity)
                findings.extend(fallback_findings)

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="abuseipdb" if api_key else "ip-api",
                confidence=0.8,
                raw_data={
                    "abuse_score": entity.metadata.get("abuse_score", 0),
                    "is_proxy": entity.metadata.get("is_proxy", False),
                },
            )

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {
                "abuseipdb": entity.metadata.get("abuseipdb_data", {}),
                "ip_api": entity.metadata.get("ip_api_data", {}),
            }

        except Exception as e:
            result.add_warning(f"Breach IP check failed: {e}")

        return result

    def _check_abuseipdb(self, ip: str, api_key: str, entity: Entity) -> list[dict]:
        findings: list[dict] = []
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "true",
            }
            resp = requests.get(url, headers=headers, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json().get("data", {})

            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "")
            isp = data.get("isp", "")
            usage = data.get("usageType", "")
            is_public = data.get("isPublic", True)
            is_whitelisted = data.get("isWhitelisted", False)

            entity.metadata["abuse_score"] = abuse_score
            entity.metadata["total_reports"] = total_reports
            entity.metadata["country"] = country
            entity.metadata["isp"] = isp
            entity.metadata["usage_type"] = usage
            entity.metadata["is_public"] = is_public
            entity.metadata["is_whitelisted"] = is_whitelisted
            entity.metadata["abuseipdb_data"] = data

            if abuse_score > 0:
                entity.add_tag("abuse-reported")

            if abuse_score >= 50:
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "AbuseIPDB Reports",
                        "status": "fail",
                        "risk": "critical" if abuse_score >= 80 else "high",
                        "message": f"IP has abuse confidence score of {abuse_score}% with {total_reports} report(s)",
                        "recommendation": "Investigate abuse reports and consider blocking.",
                    }
                )
            elif total_reports > 0:
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "AbuseIPDB Reports",
                        "status": "warn",
                        "risk": "medium",
                        "message": f"IP has {total_reports} abuse report(s) with score {abuse_score}%",
                        "recommendation": "Review abuse reports for context.",
                    }
                )
            else:
                findings.append(
                    {
                        "category": "Breach Status",
                        "check": "AbuseIPDB Reports",
                        "status": "pass",
                        "risk": "info",
                        "message": "No abuse reports found for this IP",
                        "recommendation": "",
                    }
                )

        except requests.RequestException as e:
            findings.append(
                {
                    "category": "Breach Status",
                    "check": "AbuseIPDB Reports",
                    "status": "info",
                    "risk": "info",
                    "message": f"Unable to query AbuseIPDB: {e}",
                    "recommendation": "",
                }
            )

        return findings

    def _check_ipapi(self, ip: str, entity: Entity) -> list[dict]:
        findings: list[dict] = []
        try:
            url = f"https://ip-api.com/json/{ip}"
            params = "fields=status,message,isp,org,hosting,proxy,query"
            resp = requests.get(f"{url}?{params}", timeout=10)
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") == "success":
                isp = data.get("isp", "")
                org = data.get("org", "")
                hosting = data.get("hosting", False)
                proxy = data.get("proxy", False)

                entity.metadata["isp"] = isp
                entity.metadata["org"] = org
                entity.metadata["is_hosting"] = hosting
                entity.metadata["is_proxy"] = proxy
                entity.metadata["ip_api_data"] = data

                if proxy:
                    entity.add_tag("proxy")
                    findings.append(
                        {
                            "category": "Breach Status",
                            "check": "Proxy/VPN Detection",
                            "status": "warn",
                            "risk": "medium",
                            "message": f"IP is a proxy/VPN (ISP: {isp})",
                            "recommendation": "Proxy usage may indicate anonymization. Assess risk context.",
                        }
                    )

                if hosting:
                    entity.add_tag("hosting-provider")
                    findings.append(
                        {
                            "category": "Breach Status",
                            "check": "Hosting Provider Detection",
                            "status": "info",
                            "risk": "info",
                            "message": f"IP is a hosting provider (ISP: {isp})",
                            "recommendation": "",
                        }
                    )

                if not proxy and not hosting:
                    findings.append(
                        {
                            "category": "Breach Status",
                            "check": "IP Reputation",
                            "status": "pass",
                            "risk": "info",
                            "message": f"IP appears to be a residential/standard ISP (ISP: {isp})",
                            "recommendation": "",
                        }
                    )

        except requests.RequestException as e:
            findings.append(
                {
                    "category": "Breach Status",
                    "check": "IP Reputation",
                    "status": "info",
                    "risk": "info",
                    "message": f"Unable to query ip-api: {e}",
                    "recommendation": "",
                }
            )

        return findings
