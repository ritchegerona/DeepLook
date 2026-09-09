from __future__ import annotations

import dns.exception
import dns.resolver

from deeplook.core.entity import Entity, EntityType
from deeplook.core.security_scorer import Finding, FindingStatus, RiskLevel
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class DNSSecurity(OSINTPlugin):
    name = "dns-security"
    description = "DNS security configuration audit (DMARC, SPF, DNSSEC)"
    entity_types = [EntityType.DOMAIN]
    tags = ["passive", "dns", "security"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[Finding] = []
        domain = entity.value

        dmarc_record = None
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        if dmarc_record:
            policy = "none"
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part.split("=", 1)[1]
                    break

            if policy == "none":
                findings.append(
                    Finding(
                        category="DNS Security",
                        check="dmarc_policy",
                        status=FindingStatus.WARN,
                        risk=RiskLevel.MEDIUM,
                        message="DMARC policy is 'none' (monitor only)",
                        recommendation="Upgrade DMARC policy to 'quarantine' or 'reject' for enforcement.",
                        details={"policy": policy, "record": dmarc_record},
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="DNS Security",
                        check="dmarc_policy",
                        status=FindingStatus.PASS,
                        risk=RiskLevel.INFO,
                        message=f"DMARC policy is '{policy}'",
                        details={"policy": policy, "record": dmarc_record},
                    )
                )
        else:
            findings.append(
                Finding(
                    category="DNS Security",
                    check="dmarc_present",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.CRITICAL,
                    message="No DMARC record found",
                    recommendation="Add a DMARC record (_dmarc.{domain}) to protect against email spoofing.",
                    details={"domain": domain},
                )
            )

        spf_record = None
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        if spf_record:
            if "~all" in spf_record:
                findings.append(
                    Finding(
                        category="DNS Security",
                        check="spf_strictness",
                        status=FindingStatus.WARN,
                        risk=RiskLevel.MEDIUM,
                        message="SPF uses softfail (~all) instead of hardfail (-all)",
                        recommendation="Use '-all' for strict SPF enforcement to reject unauthorized senders.",
                        details={"record": spf_record},
                    )
                )
            elif "-all" in spf_record:
                findings.append(
                    Finding(
                        category="DNS Security",
                        check="spf_strictness",
                        status=FindingStatus.PASS,
                        risk=RiskLevel.INFO,
                        message="SPF uses hardfail (-all) for strict enforcement",
                        details={"record": spf_record},
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="DNS Security",
                        check="spf_mechanism",
                        status=FindingStatus.WARN,
                        risk=RiskLevel.MEDIUM,
                        message="SPF record has no explicit fail mechanism",
                        recommendation="Add '-all' at the end of the SPF record.",
                        details={"record": spf_record},
                    )
                )
        else:
            findings.append(
                Finding(
                    category="DNS Security",
                    check="spf_present",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.HIGH,
                    message="No SPF record found",
                    recommendation="Add an SPF record (v=spf1 ...) to authorize sending mail servers.",
                    details={"domain": domain},
                )
            )

        has_dnssec = False
        try:
            answers = dns.resolver.resolve(domain, "DNSKEY")
            if answers:
                has_dnssec = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        try:
            if not has_dnssec:
                answers = dns.resolver.resolve(domain, "RRSIG")
                if answers:
                    has_dnssec = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        if has_dnssec:
            findings.append(
                Finding(
                    category="DNS Security",
                    check="dnssec_enabled",
                    status=FindingStatus.PASS,
                    risk=RiskLevel.INFO,
                    message="DNSSEC is enabled for this domain",
                    details={"dnssec": True},
                )
            )
        else:
            findings.append(
                Finding(
                    category="DNS Security",
                    check="dnssec_enabled",
                    status=FindingStatus.WARN,
                    risk=RiskLevel.LOW,
                    message="DNSSEC is not enabled for this domain",
                    recommendation="Enable DNSSEC to protect against DNS spoofing and cache poisoning.",
                    details={"dnssec": False},
                )
            )

        result.metadata["findings"] = [
            {
                "category": f.category,
                "check": f.check,
                "status": f.status.value,
                "risk": f.risk.value,
                "message": f.message,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]
        result.metadata["dmarc"] = dmarc_record
        result.metadata["spf"] = spf_record
        result.metadata["dnssec"] = has_dnssec

        entity.metadata["dns_security"] = {
            "dmarc": dmarc_record,
            "spf": spf_record,
            "dnssec": has_dnssec,
            "findings_count": len(findings),
            "failures": sum(1 for f in findings if f.status == FindingStatus.FAIL),
        }
        entity.add_provenance(source=self.name, confidence=0.95, raw_data=result.metadata)
        entity.add_tag("dns-security-checked")
        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
