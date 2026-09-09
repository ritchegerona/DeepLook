"""Tests for output formatters."""

import json

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.output.csv_export import export_csv
from deeplook.output.json_export import export_json


class TestJsonExport:
    def test_export_json(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)

        result = export_json(ws)
        data = json.loads(result)
        assert "entities" in data
        assert len(data["entities"]) == 1
        assert data["entities"][0]["value"] == "example.com"
        ws.close()

    def test_export_json_to_file(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.IP, value="8.8.8.8")
        ws.add_entity(entity)

        out_file = tmp_path / "export.json"
        export_json(ws, out_file)
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert len(data["entities"]) == 1
        ws.close()


class TestCsvExport:
    def test_export_csv(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)

        result = export_csv(ws)
        assert "example.com" in result
        assert "domain" in result
        ws.close()

    def test_export_csv_to_file(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.EMAIL, value="test@example.com")
        ws.add_entity(entity)

        out_file = tmp_path / "export.csv"
        export_csv(ws, out_file)
        assert out_file.exists()
        ws.close()
