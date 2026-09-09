"""Tests for edge model."""

from deeplook.core.edge import Edge, RelationshipType


class TestEdge:
    def test_create_edge(self):
        edge = Edge(
            source_id="src-1",
            target_id="tgt-1",
            relationship=RelationshipType.RESOLVES_TO,
        )
        assert edge.source_id == "src-1"
        assert edge.target_id == "tgt-1"
        assert edge.relationship == RelationshipType.RESOLVES_TO
        assert edge.id

    def test_label(self):
        edge = Edge(
            source_id="src-1",
            target_id="tgt-1",
            relationship=RelationshipType.RESOLVES_TO,
        )
        assert edge.label == "resolves to"

    def test_to_dict(self):
        edge = Edge(
            source_id="src-1",
            target_id="tgt-1",
            relationship=RelationshipType.RESOLVES_TO,
        )
        d = edge.to_dict()
        assert d["source_id"] == "src-1"
        assert d["relationship"] == "resolves_to"

    def test_from_dict(self):
        d = {
            "id": "test-edge",
            "source_id": "src-1",
            "target_id": "tgt-1",
            "relationship": "resolves_to",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
            "confidence": 100.0,
            "source_plugin": "test",
            "metadata": {},
        }
        edge = Edge.from_dict(d)
        assert edge.id == "test-edge"
        assert edge.relationship == RelationshipType.RESOLVES_TO

    def test_equality(self):
        e1 = Edge(source_id="a", target_id="b", relationship=RelationshipType.RESOLVES_TO)
        e2 = Edge(source_id="a", target_id="b", relationship=RelationshipType.RESOLVES_TO)
        assert e1 == e2

    def test_hash(self):
        e1 = Edge(source_id="a", target_id="b", relationship=RelationshipType.RESOLVES_TO)
        e2 = Edge(source_id="a", target_id="b", relationship=RelationshipType.RESOLVES_TO)
        assert hash(e1) == hash(e2)
