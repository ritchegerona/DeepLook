"""CLI-level tests for the pivot, attack, ingest, and watch commands."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from deeplook.cli import app
from deeplook.core.entity import create_entity
from deeplook.core.watchlist import WatchChange, WatchCheckResult, WatchItem
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


def test_cli_ai_graceful_without_key(runner, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = runner.invoke(app, ["ai", "summarize"])

    assert result.exit_code == 0
    assert "unavailable" in result.output.lower()


def test_cli_ai_query_requires_question(runner, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = runner.invoke(app, ["ai", "query"])

    assert result.exit_code == 1


def test_cli_ai_unknown_action(runner):
    result = runner.invoke(app, ["ai", "bogus"])

    assert result.exit_code == 1


def test_cli_watch_check_writes_report_and_fails_on_change(runner, tmp_path, monkeypatch):
    assert runner.invoke(app, ["watch", "add", "evil.example"]).exit_code == 0

    class _StubEngine:
        def __init__(self, workspace):
            self.workspace = workspace

        def check_all(self):
            return [
                WatchCheckResult(
                    item=WatchItem(id=1, type="domain", value="evil.example"),
                    checked_at="2026-01-01T00:00:00+00:00",
                    changes=[WatchChange(1, "evil.example", "added", "entity", "ip:1.2.3.4")],
                )
            ]

    monkeypatch.setattr("deeplook.cli.WatchlistEngine", _StubEngine)

    report = tmp_path / "runs.jsonl"
    result = runner.invoke(app, ["watch", "check", "--report", str(report), "--fail-on-change"])

    assert result.exit_code == 2
    record = json.loads(report.read_text().strip())
    assert record["changes"] == 1
    assert record["workspace"] == "default"


def test_cli_watch_check_no_change_exits_zero(runner, tmp_path, monkeypatch):
    assert runner.invoke(app, ["watch", "add", "clean.example"]).exit_code == 0

    class _StubEngine:
        def __init__(self, workspace):
            self.workspace = workspace

        def check_all(self):
            return [
                WatchCheckResult(
                    item=WatchItem(id=1, type="domain", value="clean.example"),
                    checked_at="2026-01-01T00:00:00+00:00",
                )
            ]

    monkeypatch.setattr("deeplook.cli.WatchlistEngine", _StubEngine)

    result = runner.invoke(app, ["watch", "check", "--fail-on-change"])

    assert result.exit_code == 0
