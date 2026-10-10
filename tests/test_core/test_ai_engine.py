"""Tests for the optional AI engine (offline; no network calls)."""

from __future__ import annotations

import pytest

from deeplook.core.ai_engine import AIEngine
from deeplook.core.entity import create_entity
from deeplook.core.workspace import Workspace


@pytest.fixture(autouse=True)
def _clear_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _ws(tmp_path, name="ai"):
    return Workspace(name, base_dir=tmp_path)


def test_unavailable_without_key(tmp_path):
    engine = AIEngine()
    assert engine.available is False

    ws = _ws(tmp_path)
    assert "unavailable" in engine.summarize(ws).lower()
    assert "unavailable" in engine.suggest_pivots(ws).lower()
    assert "unavailable" in engine.generate_report(ws).lower()
    assert "unavailable" in engine.natural_query(ws, "any?").lower()


def test_available_with_openai_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    engine = AIEngine()
    assert engine.available is True
    assert engine.provider == "openai"


def test_anthropic_provider_detected(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    engine = AIEngine()
    assert engine.available is True
    assert engine.provider == "anthropic"


def test_workspace_summary_counts(tmp_path):
    ws = _ws(tmp_path)
    ws.add_entity(create_entity("example.com"))

    summary = AIEngine()._workspace_summary(ws)

    assert summary["entity_count"] == 1
    assert summary["edge_count"] == 0
    assert summary["entities_by_type"]["domain"][0]["value"] == "example.com"
