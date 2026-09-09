"""Tests for graph engine."""

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.graph import IntelGraph


class TestIntelGraph:
    def test_add_entity(self):
        g = IntelGraph()
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        g.add_entity(e)
        assert g.entity_count == 1

    def test_add_edge(self):
        g = IntelGraph()
        e1 = Entity(type=EntityType.DOMAIN, value="example.com")
        e2 = Entity(type=EntityType.IP, value="8.8.8.8")
        g.add_entity(e1)
        g.add_entity(e2)
        edge = Edge(
            source_id=e1.id,
            target_id=e2.id,
            relationship=RelationshipType.RESOLVES_TO,
        )
        g.add_edge(edge)
        assert g.edge_count == 1

    def test_find_entity(self):
        g = IntelGraph()
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        g.add_entity(e)
        found = g.find_entity("example.com")
        assert found is not None
        assert found.value == "example.com"

    def test_get_neighbors(self):
        g = IntelGraph()
        e1 = Entity(type=EntityType.DOMAIN, value="example.com")
        e2 = Entity(type=EntityType.IP, value="8.8.8.8")
        g.add_entity(e1)
        g.add_entity(e2)
        edge = Edge(
            source_id=e1.id,
            target_id=e2.id,
            relationship=RelationshipType.RESOLVES_TO,
        )
        g.add_edge(edge)
        neighbors = g.get_neighbors(e1.id, "out")
        assert len(neighbors) == 1
        assert neighbors[0][0].value == "8.8.8.8"

    def test_entities_by_type(self):
        g = IntelGraph()
        g.add_entity(Entity(type=EntityType.DOMAIN, value="a.com"))
        g.add_entity(Entity(type=EntityType.DOMAIN, value="b.com"))
        g.add_entity(Entity(type=EntityType.IP, value="1.2.3.4"))
        domains = g.entities_by_type(EntityType.DOMAIN)
        assert len(domains) == 2

    def test_render_ascii(self):
        g = IntelGraph()
        g.add_entity(Entity(type=EntityType.DOMAIN, value="example.com"))
        text = g.render_ascii()
        assert "example.com" in str(text)

    def test_merge(self):
        g1 = IntelGraph()
        g1.add_entity(Entity(type=EntityType.DOMAIN, value="a.com"))
        g2 = IntelGraph()
        g2.add_entity(Entity(type=EntityType.IP, value="1.2.3.4"))
        g1.merge(g2)
        assert g1.entity_count == 2
