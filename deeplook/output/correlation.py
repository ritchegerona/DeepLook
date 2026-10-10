"""Cross-target correlation engine for DeepLook workspaces."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from deeplook.core.edge import RelationshipType
from deeplook.core.entity import EntityType
from deeplook.core.workspace import Workspace


def _find_shared_infrastructure(workspace: Workspace) -> list[dict[str, Any]]:
    ip_domains: dict[str, list[str]] = defaultdict(list)
    entity_map = {e.id: e for e in workspace.all_entities()}

    for edge in workspace.all_edges():
        if edge.relationship == RelationshipType.RESOLVES_TO:
            src = entity_map.get(edge.source_id)
            tgt = entity_map.get(edge.target_id)
            if src and tgt and src.type == EntityType.DOMAIN and tgt.type == EntityType.IP:
                ip_domains[tgt.value].append(src.value)

    findings = []
    for ip, domains in ip_domains.items():
        if len(domains) > 1:
            findings.append(
                {
                    "type": "shared_ip",
                    "ip": ip,
                    "domains": sorted(set(domains)),
                    "count": len(set(domains)),
                }
            )
    return findings


def _find_shared_contacts(workspace: Workspace) -> list[dict[str, Any]]:
    contact_map: dict[str, list[str]] = defaultdict(list)
    entity_map = {e.id: e for e in workspace.all_entities()}

    for edge in workspace.all_edges():
        if edge.relationship == RelationshipType.CONTACT_EMAIL:
            src = entity_map.get(edge.source_id)
            tgt = entity_map.get(edge.target_id)
            if src and tgt and tgt.type == EntityType.EMAIL:
                contact_map[tgt.value].append(src.value)

    findings = []
    for email, entities in contact_map.items():
        unique_entities = list(set(entities))
        if len(unique_entities) > 1:
            findings.append(
                {
                    "type": "shared_email",
                    "email": email,
                    "entities": sorted(unique_entities),
                    "count": len(unique_entities),
                }
            )
    return findings


def _find_shared_technology(workspace: Workspace) -> list[dict[str, Any]]:
    tech_map: dict[str, list[str]] = defaultdict(list)
    entity_map = {e.id: e for e in workspace.all_entities()}

    for edge in workspace.all_edges():
        if edge.relationship == RelationshipType.USES_TECH:
            src = entity_map.get(edge.source_id)
            tgt = entity_map.get(edge.target_id)
            if src and tgt:
                tech_value = tgt.value
                tech_map[tech_value].append(src.value)

    findings = []
    for tech, entities in tech_map.items():
        unique_entities = list(set(entities))
        if len(unique_entities) > 1:
            findings.append(
                {
                    "type": "shared_technology",
                    "technology": tech,
                    "entities": sorted(unique_entities),
                    "count": len(unique_entities),
                }
            )
    return findings


def _find_certificate_overlap(workspace: Workspace) -> list[dict[str, Any]]:
    cert_entities = workspace.entities_by_type(EntityType.CERT)
    entity_map = {e.id: e for e in workspace.all_entities()}

    issuer_certs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cert in cert_entities:
        issuer = cert.metadata.get("issuer", "")
        expiry = cert.metadata.get("not_after", "")
        if issuer:
            issuer_certs[issuer].append(
                {
                    "cert_id": cert.id,
                    "expiry": expiry,
                    "value": cert.value,
                }
            )

    findings = []
    for issuer, certs in issuer_certs.items():
        if len(certs) < 2:
            continue

        cert_domains: dict[str, list[str]] = defaultdict(list)
        for edge in workspace.all_edges():
            if edge.relationship == RelationshipType.CERT_ISSUED_TO:
                tgt = entity_map.get(edge.target_id)
                if tgt is not None and tgt.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
                    for cert_dict in certs:
                        if edge.source_id == cert_dict["cert_id"]:
                            cert_domains[cert_dict["value"]].append(tgt.value)

        domains = set()
        for domain_list in cert_domains.values():
            domains.update(domain_list)

        if len(domains) > 1:
            findings.append(
                {
                    "type": "shared_certificate_issuer",
                    "issuer": issuer,
                    "certificates": [c["value"] for c in certs],
                    "domains": sorted(domains),
                    "count": len(domains),
                }
            )
    return findings


def correlate(workspace: Workspace) -> dict[str, list[dict[str, Any]]]:
    return {
        "shared_infrastructure": _find_shared_infrastructure(workspace),
        "shared_contacts": _find_shared_contacts(workspace),
        "shared_technology": _find_shared_technology(workspace),
        "certificate_overlap": _find_certificate_overlap(workspace),
    }
