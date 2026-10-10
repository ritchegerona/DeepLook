"""STIX 2.1 bundle export for DeepLook workspaces."""

from __future__ import annotations

from pathlib import Path

from stix2 import Bundle, Identity, Relationship  # type: ignore[import-untyped]
from stix2.v21 import Indicator  # type: ignore[import-untyped]

from deeplook.core.edge import Edge
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace

_IDENTITY_ID = "identity--7b322e62-4f2c-44d5-b73f-c5c251b9f2c1"

_STIX_TYPE_MAP = {
    EntityType.DOMAIN: ("domain-name", "value"),
    EntityType.IP: ("ipv4-addr", "value"),
    EntityType.EMAIL: ("email-addr", "value"),
    EntityType.URL: ("url", "value"),
    EntityType.HASH: ("file", "hashes.MD5"),
}

_OBSERVABLE_MAP = {
    EntityType.DOMAIN: lambda v: {"type": "domain-name", "value": v},
    EntityType.IP: lambda v: {"type": "ipv4-addr", "value": v},
    EntityType.EMAIL: lambda v: {"type": "email-addr", "value": v},
    EntityType.URL: lambda v: {"type": "url", "value": v},
}


def _entity_to_stix(entity: Entity) -> Indicator | None:
    if entity.type in _STIX_TYPE_MAP:
        stix_type, pattern_key = _STIX_TYPE_MAP[entity.type]
        pattern = f"[{stix_type}:{pattern_key} = '{entity.value}']"
        return Indicator(
            name=entity.value,
            pattern=pattern,
            pattern_type="stix",
            valid_from=entity.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
            confidence=int(entity.confidence),
            object_marking_refs=["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
        )
    return None


def _edge_to_stix(edge: Edge, stix_id_map: dict[str, str]) -> Relationship | None:
    src_stix = stix_id_map.get(edge.source_id)
    tgt_stix = stix_id_map.get(edge.target_id)
    if not src_stix or not tgt_stix:
        return None

    return Relationship(
        relationship_type="related-to",
        source_ref=src_stix,
        target_ref=tgt_stix,
        start_time=edge.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def export_stix(workspace: Workspace, output_path: Path | None = None) -> str:
    identity = Identity(name="DeepLook Investigation", identity_class="organization")

    stix_objects: list = [identity]
    stix_id_map: dict[str, str] = {}

    for entity in workspace.all_entities():
        indicator = _entity_to_stix(entity)
        if indicator:
            stix_objects.append(indicator)
            stix_id_map[entity.id] = indicator.id

    for edge in workspace.all_edges():
        rel = _edge_to_stix(edge, stix_id_map)
        if rel:
            stix_objects.append(rel)

    bundle = Bundle(*stix_objects, allow_custom=True)
    stix_json = bundle.serialize(pretty=True)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(stix_json, encoding="utf-8")

    return stix_json
