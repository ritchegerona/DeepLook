"""Tests for workspace."""

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace


class TestWorkspace:
    def test_create_workspace(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        assert ws.db_path.exists()
        ws.close()

    def test_add_and_get_entity(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)
        found = ws.get_entity(entity.id)
        assert found is not None
        assert found.value == "example.com"
        ws.close()

    def test_find_entity_by_value(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)
        found = ws.find_entity_by_value("example.com")
        assert found is not None
        ws.close()

    def test_add_and_get_edge(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        e1 = Entity(type=EntityType.DOMAIN, value="example.com")
        e2 = Entity(type=EntityType.IP, value="8.8.8.8")
        ws.add_entity(e1)
        ws.add_entity(e2)
        edge = Edge(
            source_id=e1.id,
            target_id=e2.id,
            relationship=RelationshipType.RESOLVES_TO,
        )
        ws.add_edge(edge)
        edges = ws.edges_for_entity(e1.id)
        assert len(edges) == 1
        ws.close()

    def test_add_note(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        ws.add_note(None, "test note")
        notes = ws.get_notes()
        assert len(notes) == 1
        assert notes[0]["content"] == "test note"
        ws.close()

    def test_timeline(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        ws.add_timeline_event("test event")
        events = ws.get_timeline()
        assert len(events) == 1
        assert events[0]["event"] == "test event"
        ws.close()

    def test_search(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)
        results = ws.search("example")
        assert len(results["entities"]) == 1
        ws.close()

    def test_to_graph(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)
        graph = ws.to_graph()
        assert graph.entity_count == 1
        ws.close()

    def test_list_workspaces(self, tmp_path):
        Workspace("ws1", base_dir=tmp_path)
        Workspace("ws2", base_dir=tmp_path)
        workspaces = Workspace.list_workspaces(tmp_path)
        assert len(workspaces) == 2
