from __future__ import annotations

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class WebDnsExtraPlugin(OSINTPlugin):
    name = "web-dns-extra"
    description = "Extended DNS checks: CAA records and DNSSEC validation"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.8
    tags = ["passive", "dns", "caa", "dnssec", "security"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        import dns.exception
        import dns.resolver

        result = PluginResult()
        domain = entity.value
        caa_records: list[dict] = []
        dnssec_info: dict = {}

        try:
            answers = dns.resolver.resolve(domain, "CAA")
            for rdata in answers:
                flags = rdata.flags
                tag = rdata.tag
                value = rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
                caa_records.append(
                    {
                        "flags": flags,
                        "tag": tag,
                        "value": value,
                    }
                )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            entity.metadata["dns_extra"] = {"error": "Domain does not exist"}
            entity.add_provenance(source=self.name, confidence=0.8)
            workspace.add_entity(entity)
            result.add_entity(entity)
            return result
        except dns.resolver.NoNameservers:
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        issue_cas: list[str] = []
        issuewild_cas: list[str] = []
        for rec in caa_records:
            if rec["tag"] == "issue":
                issue_cas.append(rec["value"])
            elif rec["tag"] == "issuewild":
                issuewild_cas.append(rec["value"])

        try:
            soa_answer = dns.resolver.resolve(domain, "SOA")
            if soa_answer:
                try:
                    nameserver = str(soa_answer[0].mname)
                    dnssec_info["soa_mname"] = nameserver

                    dnskey_records = []
                    try:
                        dnskey_answer = dns.resolver.resolve(domain, "DNSKEY")
                        for rdata in dnskey_answer:
                            dnskey_records.append(
                                {
                                    "flags": rdata.flags,
                                    "protocol": rdata.protocol,
                                    "algorithm": rdata.algorithm,
                                }
                            )
                        dnssec_info["dnskey_count"] = len(dnskey_records)
                        dnssec_info["has_dnskey"] = len(dnskey_records) > 0
                    except (
                        dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers,
                        dns.exception.Timeout,
                    ):
                        dnssec_info["has_dnskey"] = False

                    rrsig_records = []
                    try:
                        rrsig_answer = dns.resolver.resolve(domain, "RRSIG")
                        for rdata in rrsig_answer:
                            rrsig_records.append(
                                {
                                    "type_covered": rdata.type_covered,
                                    "algorithm": rdata.algorithm,
                                    "labels": rdata.labels,
                                    "original_ttl": rdata.original_ttl,
                                }
                            )
                        dnssec_info["rrsig_count"] = len(rrsig_records)
                        dnssec_info["has_rrsig"] = len(rrsig_records) > 0
                    except (
                        dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers,
                        dns.exception.Timeout,
                    ):
                        dnssec_info["has_rrsig"] = False

                    dnssec_info["dnssec_enabled"] = dnssec_info.get(
                        "has_dnskey", False
                    ) and dnssec_info.get("has_rrsig", False)

                except Exception as e:
                    dnssec_info["error"] = str(e)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception:
            pass

        entity.metadata["dns_extra"] = {
            "caa_records": caa_records,
            "issue_cas": issue_cas,
            "issuewild_cas": issuewild_cas,
            "dnssec": dnssec_info,
        }

        entity.add_provenance(
            source=self.name,
            confidence=0.8,
            raw_data={
                "caa_count": len(caa_records),
                "issue_cas": issue_cas,
                "issuewild_cas": issuewild_cas,
            },
        )

        if caa_records:
            entity.add_tag("caa-records")
        if dnssec_info.get("dnssec_enabled"):
            entity.add_tag("dnssec-enabled")

        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
