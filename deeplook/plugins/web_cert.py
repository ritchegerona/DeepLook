from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

KNOWN_CAS = {
    "Let's Encrypt",
    "Cloudflare",
    "DigiCert",
    "Sectigo",
    "Comodo",
    "GlobalSign",
    "GoDaddy",
    "Amazon",
    "Google Trust Services",
    "Entrust",
    "IdenTrust",
    "ZeroSSL",
    "Buypass",
}


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


@register_plugin
class WebCert(OSINTPlugin):
    name = "web-cert"
    description = "TLS certificate chain inspection for web domains"
    entity_types = [EntityType.DOMAIN]
    tags = ["active", "web", "certificate"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=entity.value) as s:
                s.settimeout(10)
                s.connect((entity.value, 443))
                cert = s.getpeercert()
        except ssl.SSLCertVerificationError as e:
            result.add_warning(f"SSL verification failed for {entity.value}: {e}")
            entity.metadata["certificate"] = {"error": str(e), "verified": False}
            entity.add_provenance(source=self.name, confidence=0.5)
            workspace.add_entity(entity)
            result.add_entity(entity)
            return result
        except ssl.SSLError as e:
            result.add_warning(f"SSL error for {entity.value}: {e}")
            entity.metadata["certificate"] = {"error": str(e)}
            entity.add_provenance(source=self.name, confidence=0.3)
            workspace.add_entity(entity)
            result.add_entity(entity)
            return result
        except socket.gaierror:
            result.add_warning(f"Could not resolve {entity.value}")
            return result
        except TimeoutError:
            result.add_warning(f"Connection timed out for {entity.value}")
            return result
        except ConnectionRefusedError:
            result.add_warning(f"Connection refused for {entity.value}:443")
            return result
        except Exception as e:
            result.add_warning(f"Certificate inspection failed for {entity.value}: {e}")
            return result

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        san_list = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            san_list.append(san_value)

        issuer_org = issuer.get("organizationName", "Unknown")
        is_self_signed = subject == issuer
        is_expired = False
        not_after_dt = _parse_cert_date(not_after)
        if not_after_dt and not_after_dt < datetime.now(UTC):
            is_expired = True

        known_ca = any(ca.lower() in issuer_org.lower() for ca in KNOWN_CAS)

        cert_data = {
            "subject": dict(subject),
            "issuer": dict(issuer),
            "issuer_org": issuer_org,
            "serial_number": cert.get("serialNumber", ""),
            "not_before": not_before,
            "not_after": not_after,
            "san": san_list,
            "version": cert.get("version", ""),
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "known_ca": known_ca,
        }

        entity.metadata["certificate"] = cert_data
        entity.add_provenance(source=self.name, confidence=0.95, raw_data=cert_data)
        entity.add_tag("cert-inspected")
        if is_expired:
            entity.add_tag("cert-expired")
        if is_self_signed:
            entity.add_tag("cert-self-signed")
        workspace.add_entity(entity)
        result.add_entity(entity)

        issuer_value = issuer.get("commonName", issuer_org)
        cert_entity = Entity(type=EntityType.CERT, value=issuer_value, confidence=95.0)
        cert_entity.add_provenance(source=self.name, confidence=0.95)
        cert_entity.add_tag("certificate-authority")
        workspace.add_entity(cert_entity)
        result.add_entity(cert_entity)

        edge = Edge(
            source_id=cert_entity.id,
            target_id=entity.id,
            relationship=RelationshipType.CERT_ISSUED_TO,
            source_plugin=self.name,
            confidence=95.0,
            metadata={"is_self_signed": is_self_signed, "is_expired": is_expired},
        )
        workspace.add_edge(edge)
        result.add_edge(edge)

        return result
