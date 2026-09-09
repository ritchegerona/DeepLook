from __future__ import annotations

import dns.resolver
import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

VULNERABLE_CNAMES = {
    "s3.amazonaws.com",
    "s3-website",
    "herokuapp.com",
    "github.io",
    "ghost.io",
    "shopify.com",
    "myshopify.com",
    "surge.sh",
    "bitbucket.io",
    "azurewebsites.net",
    "cloudapp.net",
    "azure-api.net",
    "azureedge.net",
    "azurecontainer.io",
    "database.windows.net",
    "azuredatalakestore.net",
    "search.windows.net",
    "azurecr.io",
    "redis.cache.windows.net",
    "azurehdinsight.net",
    "servicebus.windows.net",
    "visualstudio.com",
    "trafficmanager.net",
    "blob.core.windows.net",
    "azurewebsites.net",
    "pingidentity.net",
    "squarespace.com",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "elb.amazonaws.com",
    "pages.github.io",
    "zendesk.com",
    "readme.io",
    "pantheon.io",
    "ghost.org",
    "strikingly.com",
    "helpjuice.com",
    "helpscoutdocs.com",
    "cargocollective.com",
    "fastly.net",
    "feedpress.me",
    "ghost.io",
    "helpjuice.com",
    "helpscoutdocs.com",
    "heroku.com",
    "instapage.com",
    "launchrock.com",
    "mouseoutside.com",
    "ngrok.io",
    "pingdom.com",
    "proposify.biz",
    "readme.io",
    "s3-us-west-2.amazonaws.com",
    "squarespace.com",
    "statuspage.io",
    "strikingly.com",
    "surge.sh",
    "tave.com",
    "teamwork.com",
    "thinkific.com",
    "tictail.com",
    "tumblr.com",
    "uberflip.com",
    "uservoice.com",
    "vend.com",
    "wordpress.com",
    "zendesk.com",
}


def _check_cname(subdomain: str) -> list[str]:
    cnames: list[str] = []
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            cnames.append(str(rdata.target).rstrip("."))
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    try:
        answers = dns.resolver.resolve(subdomain, "A")
        for rdata in answers:
            cnames.append(str(rdata))
    except Exception:
        pass

    return cnames


@register_plugin
class SubdomainTakeoverPlugin(OSINTPlugin):
    name = "subdomain-takeover"
    description = "Check for subdomain takeover vulnerabilities via CNAME records"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.75
    tags = ["subdomain", "takeover", "cname", "exposure"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[dict] = []

        try:
            domain = entity.value.strip().lower()

            subdomains = self._fetch_subdomains(domain)
            entity.metadata["subdomain_count"] = len(subdomains)

            vulnerable_subs = []
            for sub in subdomains:
                cnames = _check_cname(sub)
                for cname in cnames:
                    for vuln_target in VULNERABLE_CNAMES:
                        if vuln_target in cname:
                            vulnerable_subs.append(
                                {
                                    "subdomain": sub,
                                    "cname": cname,
                                    "target": vuln_target,
                                }
                            )
                            break

            if vulnerable_subs:
                for vs in vulnerable_subs:
                    findings.append(
                        {
                            "category": "Exposure Risk",
                            "check": "Subdomain Takeover",
                            "status": "fail",
                            "risk": "critical",
                            "message": (
                                f"Subdomain {vs['subdomain']} has CNAME pointing to "
                                f"{vs['cname']} ({vs['target']}) - potential takeover"
                            ),
                            "recommendation": (
                                f"Remove or reclaim the CNAME record for {vs['subdomain']} "
                                f"or ensure the target service is properly claimed."
                            ),
                        }
                    )
                    entity.add_tag("takeover-vulnerable")
            else:
                findings.append(
                    {
                        "category": "Exposure Risk",
                        "check": "Subdomain Takeover",
                        "status": "pass",
                        "risk": "info",
                        "message": f"No vulnerable CNAME records found across {len(subdomains)} subdomains",
                        "recommendation": "",
                    }
                )

            result.metadata["findings"] = findings

            entity.add_provenance(
                source="subdomain-takeover",
                confidence=0.75,
                raw_data={
                    "subdomains_checked": len(subdomains),
                    "vulnerable": vulnerable_subs,
                },
            )

            workspace.add_entity(entity)
            result.add_entity(entity)
            result.raw_data = {
                "subdomains": subdomains[:50],
                "vulnerable": vulnerable_subs,
            }

        except Exception as e:
            result.add_warning(f"Subdomain takeover check failed: {e}")

        return result

    def _fetch_subdomains(self, domain: str) -> list[str]:
        subdomains: list[str] = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
            seen: set[str] = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and sub not in seen and sub.endswith(domain):
                        seen.add(sub)
                        subdomains.append(sub)
        except requests.RequestException:
            pass
        except (ValueError, KeyError):
            pass

        return subdomains
