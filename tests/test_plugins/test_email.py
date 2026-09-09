"""Tests for email-syntax plugin."""

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.email_syntax import EmailSyntax


class TestEmailSyntaxPlugin:
    def test_valid_email(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        plugin = EmailSyntax()
        entity = Entity(type=EntityType.EMAIL, value="user@example.com")
        result = plugin.run(entity, ws)
        assert len(result.entities) >= 1
        ws.close()

    def test_invalid_email(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        plugin = EmailSyntax()
        entity = Entity(type=EntityType.EMAIL, value="not-an-email")
        result = plugin.run(entity, ws)
        assert len(result.entities) == 1
        assert "invalid-email" in result.entities[0].tags
        assert result.entities[0].metadata.get("valid_syntax") is False
        ws.close()
