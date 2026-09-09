from __future__ import annotations

import dns.resolver

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class DomainDNS(OSINTPlugin):
    name = "domain-dns"
    description = "DNS record lookup for domain systems"
    entity_types = [EntityType.DOMAIN]
    tags = ["passive", "dns"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        dns_data: dict[str, list[str]] = {}

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(entity.value, rtype)
                records = []
                for rdata in answers:
                    if rtype == "MX":
                        records.append(f"{rdata.exchange} (priority={rdata.preference})")
                    elif rtype == "SOA":
                        records.append(f"{rdata.mname} {rdata.rname} serial={rdata.serial}")
                    else:
                        records.append(str(rdata))
                dns_data[rtype] = records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue

        if not dns_data:
            result.add_warning(f"No DNS records found for {entity.value}")
            return result

        entity.metadata["dns_records"] = dns_data
        entity.add_provenance(source=self.name, confidence=0.95, raw_data=dns_data)
        entity.add_tag("dns-looked-up")
        workspace.add_entity(entity)
        result.add_entity(entity)

        for a_record in dns_data.get("A", []):
            ip_entity = Entity(type=EntityType.IP, value=a_record, confidence=95.0)
            ip_entity.add_provenance(source=self.name, confidence=0.95)
            workspace.add_entity(ip_entity)
            result.add_entity(ip_entity)
            edge = Edge(
                source_id=entity.id,
                target_id=ip_entity.id,
                relationship=RelationshipType.RESOLVES_TO,
                source_plugin=self.name,
                confidence=95.0,
                metadata={"record_type": "A"},
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        for aaaa_record in dns_data.get("AAAA", []):
            ip_entity = Entity(type=EntityType.IP, value=aaaa_record, confidence=95.0)
            ip_entity.add_provenance(source=self.name, confidence=0.95)
            workspace.add_entity(ip_entity)
            result.add_entity(ip_entity)
            edge = Edge(
                source_id=entity.id,
                target_id=ip_entity.id,
                relationship=RelationshipType.RESOLVES_TO,
                source_plugin=self.name,
                confidence=95.0,
                metadata={"record_type": "AAAA"},
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        for mx_record in dns_data.get("MX", []):
            mx_host = mx_record.split(" ")[0].rstrip(".")
            mx_entity = Entity(type=EntityType.DOMAIN, value=mx_host, confidence=90.0)
            mx_entity.add_provenance(source=self.name, confidence=0.9)
            mx_entity.add_tag("mx-record")
            workspace.add_entity(mx_entity)
            result.add_entity(mx_entity)
            edge = Edge(
                source_id=entity.id,
                target_id=mx_entity.id,
                relationship=RelationshipType.MX_RECORD,
                source_plugin=self.name,
                confidence=90.0,
                metadata={"raw": mx_record},
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        for ns_record in dns_data.get("NS", []):
            ns_host = ns_record.rstrip(".")
            ns_entity = Entity(type=EntityType.DOMAIN, value=ns_host, confidence=90.0)
            ns_entity.add_provenance(source=self.name, confidence=0.9)
            ns_entity.add_tag("ns-record")
            workspace.add_entity(ns_entity)
            result.add_entity(ns_entity)
            edge = Edge(
                source_id=entity.id,
                target_id=ns_entity.id,
                relationship=RelationshipType.NS_RECORD,
                source_plugin=self.name,
                confidence=90.0,
            )
            workspace.add_edge(edge)
            result.add_edge(edge)

        return result
