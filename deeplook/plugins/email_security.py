from __future__ import annotations

import dns.exception
import dns.resolver

from deeplook.core.entity import Entity, EntityType
from deeplook.core.security_scorer import Finding, FindingStatus, RiskLevel
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mandrill", "everlytickey1"]


@register_plugin
class EmailSecurity(OSINTPlugin):
    name = "email-security"
    description = "Email security configuration audit (DMARC, SPF, DKIM)"
    entity_types = [EntityType.DOMAIN]
    tags = ["passive", "dns", "email", "security"]

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
                        category="Email Security",
                        check="dmarc_policy",
                        status=FindingStatus.WARN,
                        risk=RiskLevel.MEDIUM,
                        message="DMARC policy is 'none' (monitor only)",
                        recommendation="Upgrade DMARC policy to 'quarantine' or 'reject' to block spoofed emails.",
                        details={"policy": policy, "record": dmarc_record},
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="Email Security",
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
                    category="Email Security",
                    check="dmarc_present",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.CRITICAL,
                    message="No DMARC record found for this domain",
                    recommendation="Add a DMARC record (_dmarc.{domain}) to prevent email spoofing and phishing.",
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
            has_includes = "include:" in spf_record
            has_ip = any(x in spf_record for x in ["ip4:", "ip6:"])
            if "~all" in spf_record:
                findings.append(
                    Finding(
                        category="Email Security",
                        check="spf_record",
                        status=FindingStatus.WARN,
                        risk=RiskLevel.MEDIUM,
                        message="SPF uses softfail (~all) - unauthorized senders are tagged but not rejected",
                        recommendation="Use '-all' to reject unauthorized senders outright.",
                        details={
                            "record": spf_record,
                            "has_includes": has_includes,
                            "has_ip": has_ip,
                        },
                    )
                )
            elif "-all" in spf_record:
                findings.append(
                    Finding(
                        category="Email Security",
                        check="spf_record",
                        status=FindingStatus.PASS,
                        risk=RiskLevel.INFO,
                        message="SPF record is properly configured with hardfail",
                        details={
                            "record": spf_record,
                            "has_includes": has_includes,
                            "has_ip": has_ip,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="Email Security",
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
                    category="Email Security",
                    check="spf_present",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.HIGH,
                    message="No SPF record found for this domain",
                    recommendation="Add an SPF record (v=spf1 -all) to authorize sending mail servers.",
                    details={"domain": domain},
                )
            )

        dkim_found = False
        dkim_selector = None
        for selector in DKIM_SELECTORS:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                if answers:
                    dkim_found = True
                    dkim_selector = selector
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                continue
            except Exception:
                continue

        if dkim_found:
            findings.append(
                Finding(
                    category="Email Security",
                    check="dkim_present",
                    status=FindingStatus.PASS,
                    risk=RiskLevel.INFO,
                    message=f"DKIM record found with selector '{dkim_selector}'",
                    details={"selector": dkim_selector},
                )
            )
        else:
            findings.append(
                Finding(
                    category="Email Security",
                    check="dkim_present",
                    status=FindingStatus.WARN,
                    risk=RiskLevel.MEDIUM,
                    message="No DKIM record found (checked common selectors)",
                    recommendation="Configure DKIM signing for your email domain to prevent tampering.",
                    details={"checked_selectors": DKIM_SELECTORS},
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
        result.metadata["dkim_found"] = dkim_found
        result.metadata["dkim_selector"] = dkim_selector

        entity.metadata["email_security"] = {
            "dmarc": dmarc_record,
            "spf": spf_record,
            "dkim_found": dkim_found,
            "dkim_selector": dkim_selector,
            "findings_count": len(findings),
            "failures": sum(1 for f in findings if f.status == FindingStatus.FAIL),
        }
        entity.add_provenance(source=self.name, confidence=0.95, raw_data=result.metadata)
        entity.add_tag("email-security-checked")
        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
