from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from deeplook.core.entity import Entity, EntityType
from deeplook.core.security_scorer import Finding, FindingStatus, RiskLevel
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
WEAK_CIPHER_PATTERNS = ["rc4", "des", "null", "export", "md5", "rc2"]


def _parse_cert_date(date_str: str) -> datetime | None:
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%Y%m%d%H%M%SZ",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _check_weak_ciphers(protocol: str, cipher_name: str) -> tuple[bool, str]:
    cipher_lower = cipher_name.lower()
    for pattern in WEAK_CIPHER_PATTERNS:
        if pattern in cipher_lower:
            return True, pattern.upper()
    return False, ""


@register_plugin
class SSLVuln(OSINTPlugin):
    name = "ssl-vuln"
    description = "SSL/TLS vulnerability and misconfiguration detection"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "security", "ssl", "tls"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        findings: list[Finding] = []

        try:
            ctx_check = ssl.create_default_context()
            with ctx_check.wrap_socket(socket.socket(), server_hostname=entity.value) as s:
                s.settimeout(10)
                s.connect((entity.value, 443))
                cert = s.getpeercert()
                protocol_version = s.version()
                cipher_info = s.cipher()
                cipher_name = cipher_info[0] if cipher_info else "unknown"
                cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0
        except ssl.SSLCertVerificationError as e:
            entity.metadata["ssl_error"] = str(e)
            entity.add_provenance(source=self.name, confidence=0.5)
            workspace.add_entity(entity)
            result.add_entity(entity)
            result.add_warning(f"SSL verification failed for {entity.value}: {e}")
            return result
        except ssl.SSLError as e:
            entity.metadata["ssl_error"] = str(e)
            entity.add_provenance(source=self.name, confidence=0.3)
            workspace.add_entity(entity)
            result.add_entity(entity)
            result.add_warning(f"SSL error for {entity.value}: {e}")
            return result
        except socket.gaierror:
            result.add_warning(f"Could not resolve {entity.value}")
            return result
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            result.add_warning(f"Connection failed for {entity.value}: {e}")
            return result
        except Exception as e:
            result.add_warning(f"SSL vulnerability check failed for {entity.value}: {e}")
            return result

        proto = protocol_version or ""
        if proto in WEAK_PROTOCOLS or any(p in proto for p in WEAK_PROTOCOLS):
            findings.append(
                Finding(
                    category="SSL/TLS Security",
                    check="protocol_version",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.CRITICAL,
                    message=f"Weak protocol detected: {protocol_version}",
                    recommendation="Disable SSLv2/SSLv3/TLS1.0/TLS1.1. Use TLS 1.2 or 1.3.",
                    details={"protocol": protocol_version},
                )
            )
        else:
            findings.append(
                Finding(
                    category="SSL/TLS Security",
                    check="protocol_version",
                    status=FindingStatus.PASS,
                    risk=RiskLevel.INFO,
                    message=f"Protocol version is secure: {protocol_version}",
                    details={"protocol": protocol_version},
                )
            )

        is_weak_cipher, weak_type = _check_weak_ciphers(proto, cipher_name)
        if is_weak_cipher:
            findings.append(
                Finding(
                    category="SSL/TLS Security",
                    check="cipher_suite",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.HIGH,
                    message=f"Weak cipher detected: {cipher_name} ({weak_type})",
                    recommendation="Disable weak cipher suites. Use AES-GCM or ChaCha20.",
                    details={"cipher": cipher_name, "bits": cipher_bits, "weak_type": weak_type},
                )
            )
        else:
            findings.append(
                Finding(
                    category="SSL/TLS Security",
                    check="cipher_suite",
                    status=FindingStatus.PASS,
                    risk=RiskLevel.INFO,
                    message=f"Cipher suite is acceptable: {cipher_name} ({cipher_bits} bits)",
                    details={"cipher": cipher_name, "bits": cipher_bits},
                )
            )

        if cert:
            not_after = cert.get("notAfter", "")  # type: ignore[union-attr]
            not_after_dt = _parse_cert_date(str(not_after)) if not_after else None
            if not_after_dt and not_after_dt < datetime.now(UTC):
                findings.append(
                    Finding(
                        category="SSL/TLS Security",
                        check="certificate_expiry",
                        status=FindingStatus.FAIL,
                        risk=RiskLevel.HIGH,
                        message=f"Certificate expired on {not_after}",
                        recommendation="Renew the SSL certificate immediately.",
                        details={"not_after": not_after},
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="SSL/TLS Security",
                        check="certificate_expiry",
                        status=FindingStatus.PASS,
                        risk=RiskLevel.INFO,
                        message=f"Certificate is valid until {not_after}",
                        details={"not_after": not_after},
                    )
                )

            subject = dict(x[0] for x in cert.get("subject", ()))  # type: ignore[misc, union-attr]
            issuer = dict(x[0] for x in cert.get("issuer", ()))  # type: ignore[misc, union-attr]
            if subject == issuer:
                findings.append(
                    Finding(
                        category="SSL/TLS Security",
                        check="self_signed",
                        status=FindingStatus.FAIL,
                        risk=RiskLevel.HIGH,
                        message="Certificate is self-signed",
                        recommendation="Use a certificate from a trusted CA.",
                        details={"subject": dict(subject), "issuer": dict(issuer)},
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="SSL/TLS Security",
                        check="self_signed",
                        status=FindingStatus.PASS,
                        risk=RiskLevel.INFO,
                        message="Certificate is signed by a trusted CA",
                        details={"issuer_org": issuer.get("organizationName", "Unknown")},
                    )
                )

            key_bits = cipher_bits
            issuer.get("organizationName", "")
            if key_bits > 0 and key_bits < 2048:
                findings.append(
                    Finding(
                        category="SSL/TLS Security",
                        check="key_strength",
                        status=FindingStatus.FAIL,
                        risk=RiskLevel.HIGH,
                        message=f"Weak key strength: {key_bits} bits",
                        recommendation="Use at least 2048-bit RSA or 256-bit ECC keys.",
                        details={"key_bits": key_bits},
                    )
                )
            elif key_bits >= 2048:
                findings.append(
                    Finding(
                        category="SSL/TLS Security",
                        check="key_strength",
                        status=FindingStatus.PASS,
                        risk=RiskLevel.INFO,
                        message=f"Key strength is adequate: {key_bits} bits",
                        details={"key_bits": key_bits},
                    )
                )
        else:
            findings.append(
                Finding(
                    category="SSL/TLS Security",
                    check="certificate_present",
                    status=FindingStatus.FAIL,
                    risk=RiskLevel.HIGH,
                    message="No certificate received from server",
                    recommendation="Ensure the server is configured with a valid SSL certificate.",
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
        result.metadata["protocol"] = protocol_version
        result.metadata["cipher"] = cipher_name
        result.metadata["cipher_bits"] = cipher_bits

        entity.metadata["ssl_vuln"] = {
            "protocol": protocol_version,
            "cipher": cipher_name,
            "cipher_bits": cipher_bits,
            "findings_count": len(findings),
            "failures": sum(1 for f in findings if f.status == FindingStatus.FAIL),
        }
        entity.add_provenance(source=self.name, confidence=0.95, raw_data=result.metadata)
        entity.add_tag("ssl-vuln-checked")
        workspace.add_entity(entity)
        result.add_entity(entity)

        return result
