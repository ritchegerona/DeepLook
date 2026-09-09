from __future__ import annotations

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

PROVIDER_MAP = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "microsoft.com": "Microsoft 365",
    "protonmail.ch": "ProtonMail",
    "proton.me": "ProtonMail",
    "zoho.com": "Zoho Mail",
    "yandex.ru": "Yandex Mail",
    "yandex.net": "Yandex Mail",
    "icloud.com": "iCloud Mail",
    "me.com": "iCloud Mail",
    "fastmail.com": "Fastmail",
    "mxlogic.com": "McAfee Email Security",
    "mimecast.com": "Mimecast",
    "barracudanetworks.com": "Barracuda",
    "proofpoint.com": "Proofpoint",
}


def _detect_provider(mx_host: str) -> str | None:
    mx_lower = mx_host.lower().rstrip(".")
    for domain, provider in PROVIDER_MAP.items():
        if mx_lower.endswith(domain) or domain in mx_lower:
            return provider
    return None


@register_plugin
class EmailMx(OSINTPlugin):
    name = "email-mx"
    description = "MX record validation and mail provider detection"
    entity_types = [EntityType.EMAIL]
    tags = ["passive", "email", "dns"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        import dns.exception
        import dns.resolver

        result = PluginResult()
        try:
            email = entity.value.strip().lower()
            if "@" not in email:
                result.add_warning(f"Invalid email format: {email}")
                return result

            domain_part = email.split("@", 1)[1]
            mx_records: list[dict] = []
            providers: list[str] = []

            try:
                answers = dns.resolver.resolve(domain_part, "MX")
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    priority = rdata.preference
                    provider = _detect_provider(mx_host)

                    mx_entry = {
                        "host": mx_host,
                        "priority": priority,
                        "provider": provider,
                    }
                    mx_records.append(mx_entry)

                    if provider and provider not in providers:
                        providers.append(provider)

                    mx_entity = Entity(type=EntityType.DOMAIN, value=mx_host, confidence=90.0)
                    mx_entity.add_provenance(source=self.name, confidence=0.9, raw_data=mx_entry)
                    mx_entity.add_tag("mx-server")
                    workspace.add_entity(mx_entity)
                    result.add_entity(mx_entity)

                    mx_edge = Edge(
                        source_id=entity.id,
                        target_id=mx_entity.id,
                        relationship=RelationshipType.MX_RECORD,
                        source_plugin=self.name,
                        confidence=90.0,
                        metadata={"priority": priority, "provider": provider},
                    )
                    workspace.add_edge(mx_edge)
                    result.add_edge(mx_edge)

            except dns.resolver.NXDOMAIN:
                entity.metadata["mx_error"] = "Domain does not exist"
            except dns.resolver.NoAnswer:
                entity.metadata["mx_error"] = "No MX records found"
            except dns.resolver.NoNameservers:
                entity.metadata["mx_error"] = "No nameservers reachable"
            except dns.exception.Timeout:
                entity.metadata["mx_error"] = "DNS query timed out"

            entity.metadata["mx_records"] = mx_records
            entity.metadata["mail_providers"] = providers
            entity.metadata["has_mx"] = len(mx_records) > 0

            if providers:
                entity.add_tag("identified-mail-provider")

            entity.add_provenance(
                source=self.name,
                confidence=0.9,
                raw_data={"mx_records": mx_records, "providers": providers},
            )
            workspace.add_entity(entity)
            result.add_entity(entity)

        except Exception as e:
            result.add_warning(f"MX lookup failed for {entity.value}: {e}")
            entity.metadata["mx_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
