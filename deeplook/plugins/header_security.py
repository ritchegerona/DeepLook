from __future__ import annotations

import requests

from deeplook.core.entity import Entity, EntityType
from deeplook.core.security_scorer import Finding, FindingStatus, RiskLevel
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

CRITICAL_HEADERS = {
    "Content-Security-Policy": "Protects against XSS and data injection attacks",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-Frame-Options": "Prevents clickjacking attacks",
}

RECOMMENDED_HEADERS = {
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "X-XSS-Protection": "Enables browser XSS filtering (legacy)",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser features and APIs",
}


@register_plugin
class HeaderSecurity(OSINTPlugin):
    name = "header-security"
    description = "HTTP security header compliance analysis"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web", "security", "headers"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[Finding] = []
        domain = entity.value

        headers = None
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                resp = requests.head(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "DeepLook OSINT Framework"},
                )
                headers = {k: v for k, v in resp.headers.items()}
                break
            except requests.ConnectionError:
                continue
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue
            except Exception:
                continue

        if headers is None:
            result.add_warning(f"Could not fetch headers for {domain}")
            entity.metadata["security_headers"] = {}
            entity.metadata["missing_critical"] = list(CRITICAL_HEADERS.keys())
            entity.metadata["missing_recommended"] = list(RECOMMENDED_HEADERS.keys())
            entity.add_provenance(source=self.name, confidence=0.3)
            workspace.add_entity(entity)
            result.add_entity(entity)
            result.metadata["findings"] = []
            return result

        found_critical = {}
        missing_critical = []
        for header, desc in CRITICAL_HEADERS.items():
            if header in headers:
                found_critical[header] = headers[header]
            else:
                missing_critical.append(header)
                findings.append(
                    Finding(
                        category="Security Headers",
                        check=header,
                        status=FindingStatus.FAIL,
                        risk=RiskLevel.HIGH,
                        message=f"Missing critical security header: {header}",
                        recommendation=f"Add '{header}' header. {desc}",
                        details={"description": desc},
                    )
                )

        found_recommended = {}
        missing_recommended = []
        for header, desc in RECOMMENDED_HEADERS.items():
            if header in headers:
                found_recommended[header] = headers[header]
            else:
                missing_recommended.append(header)
                findings.append(
                    Finding(
                        category="Security Headers",
                        check=header,
                        status=FindingStatus.WARN,
                        risk=RiskLevel.MEDIUM,
                        message=f"Missing recommended security header: {header}",
                        recommendation=f"Add '{header}' header. {desc}",
                        details={"description": desc},
                    )
                )

        if not missing_critical and not missing_recommended:
            findings.append(
                Finding(
                    category="Security Headers",
                    check="all_headers_present",
                    status=FindingStatus.PASS,
                    risk=RiskLevel.INFO,
                    message="All critical and recommended security headers are present",
                    details={
                        "critical": list(found_critical.keys()),
                        "recommended": list(found_recommended.keys()),
                    },
                )
            )

        total = len(CRITICAL_HEADERS) + len(RECOMMENDED_HEADERS)
        found_count = len(found_critical) + len(found_recommended)
        score = round(found_count / total * 100, 1) if total > 0 else 0

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
        result.metadata["security_score"] = score
        result.metadata["found_critical"] = list(found_critical.keys())
        result.metadata["missing_critical"] = missing_critical
        result.metadata["found_recommended"] = list(found_recommended.keys())
        result.metadata["missing_recommended"] = missing_recommended

        entity.metadata["security_headers"] = found_critical | found_recommended
        entity.metadata["missing_security_headers"] = missing_critical + missing_recommended
        entity.metadata["missing_critical"] = missing_critical
        entity.metadata["missing_recommended"] = missing_recommended
        entity.metadata["security_score"] = score
        entity.add_provenance(source=self.name, confidence=0.95, raw_data=result.metadata)
        entity.add_tag("header-security-checked")
        if missing_critical:
            entity.add_tag("missing-critical-headers")
        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
