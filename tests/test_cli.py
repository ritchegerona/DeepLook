"""CLI-level tests for the pivot, attack, ingest, and watch commands."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from deeplook.cli import app
from deeplook.core.entity import create_entity
from deeplook.core.workspace import Workspace


@pytest.fixture
def runner(tmp_path, monkeypatch):
    def fake_get_workspace(name=None):
        return Workspace(name or "default", base_dir=tmp_path)

    monkeypatch.setattr("deeplook.cli.get_workspace", fake_get_workspace)
    return CliRunner()


def test_cli_ingest_text(runner, tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("evil[.]com\n8.8.8.8\nevil.com\n")

    result = runner.invoke(app, ["ingest", "-f", str(feed), "--tags", "demo"])

    assert result.exit_code == 0
    assert "Added" in result.output
    assert "evil.com" in result.output


def test_cli_ingest_missing_file_exits_nonzero(runner, tmp_path):
    result = runner.invoke(app, ["ingest", "-f", str(tmp_path / "nope.txt")])
    assert result.exit_code == 1


def test_cli_watch_lifecycle(runner):
    added = runner.invoke(app, ["watch", "add", "evil[.]com", "--tags", "c2"])
    assert added.exit_code == 0
    assert "Watching domain 'evil.com'" in added.output

    listed = runner.invoke(app, ["watch", "list"])
    assert listed.exit_code == 0
    assert "evil.com" in listed.output

    removed = runner.invoke(app, ["watch", "remove", "1"])
    assert removed.exit_code == 0
    assert "Removed watch 1" in removed.output


def test_cli_attack_json(runner, tmp_path):
    ws = Workspace("default", base_dir=tmp_path)
    entity = create_entity("example.com")
    entity.add_provenance(source="domain-dns", confidence=0.9)
    ws.add_entity(entity)

    result = runner.invoke(app, ["attack", "-f", "json"])

    assert result.exit_code == 0
    assert '"technique_count"' in result.output


def test_cli_pivot_depth_zero(runner):
    result = runner.invoke(app, ["pivot", "example.com", "--depth", "0"])

    assert result.exit_code == 0
    assert "Pivot from example.com" in result.output
