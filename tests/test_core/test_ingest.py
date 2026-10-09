"""Tests for IOC ingestion and defang/refang helpers."""

from __future__ import annotations

import json
from pathlib import Path

from deeplook.core.entity import create_entity, defang, refang
from deeplook.core.ingest import (
    detect_format,
    ingest_file,
    parse_csv,
    parse_misp,
    parse_stix,
    parse_text,
)
from deeplook.core.workspace import Workspace


def _ws(tmp_path, name="ingest"):
    return Workspace(name, base_dir=tmp_path)


def test_defang_and_refang_roundtrip():
    original = "http://evil.example.com/login"
    assert defang(original) == "hxxp[://]evil[.]example[.]com/login"
    assert refang(defang(original)) == original


def test_refang_variants():
    assert refang("evil[.]com") == "evil.com"
    assert refang("evil(.)com") == "evil.com"
    assert refang("hxxp://evil[.]com") == "http://evil.com"
    assert refang("admin[@]evil[.]com") == "admin@evil.com"
    assert refang("evil[DOT]com") == "evil.com"


def test_create_entity_refangs_defanged_domain():
    entity = create_entity("evil[.]com")
    assert entity.type.value == "domain"
    assert entity.value == "evil.com"


def test_parse_text_skips_comments_and_blanks():
    raw = "# comment\n\nevil.com\n8.8.8.8  # inline\n// another\n"
    assert parse_text(raw) == ["evil.com", "8.8.8.8"]


def test_parse_csv_skips_header():
    raw = "value,type\nevil.com,domain\n8.8.8.8,ip\n"
    assert parse_csv(raw) == ["evil.com", "8.8.8.8"]


def test_parse_stix_extracts_indicator_patterns():
    bundle = json.dumps(
        {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "pattern": "[domain-name:value = 'evil.com']"},
                {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
            ],
        }
    )
    assert parse_stix(bundle) == ["evil.com", "1.2.3.4"]


def test_parse_misp_extracts_attribute_values():
    event = {"Event": {"Attribute": [{"value": "evil.com"}, {"value": "1.2.3.4"}]}}
    assert parse_misp(json.dumps(event)) == ["evil.com", "1.2.3.4"]


def test_detect_format():
    assert detect_format(Path("feed.csv"), "a,b") == "csv"
    assert detect_format(Path("feed.json"), json.dumps({"type": "bundle", "objects": []})) == "stix"
    assert detect_format(Path("feed.txt"), "evil.com\n") == "text"


def test_ingest_text_file_adds_and_dedupes(tmp_path):
    ws = _ws(tmp_path)
    feed = tmp_path / "feed.txt"
    feed.write_text("evil[.]com\n8.8.8.8\nevil.com\nnot an indicator\n")

    result = ingest_file(ws, feed, tags=["apt-test"])

    assert result.format == "text"
    assert result.added == 2
    assert result.skipped == 2
    assert len(result.errors) == 1

    entity = ws.find_entity_by_value("evil.com")
    assert "apt-test" in entity.tags
    assert "ingested" in entity.tags
    assert entity.provenance[-1].source == "ingest:feed.txt"


def test_ingest_is_idempotent(tmp_path):
    ws = _ws(tmp_path)
    feed = tmp_path / "feed.txt"
    feed.write_text("evil.com\n")

    first = ingest_file(ws, feed)
    second = ingest_file(ws, feed)

    assert first.added == 1
    assert second.added == 0
    assert second.skipped == 1


def test_ingest_stix_file(tmp_path):
    ws = _ws(tmp_path)
    feed = tmp_path / "feed.stix"
    feed.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"}],
            }
        )
    )

    result = ingest_file(ws, feed)

    assert result.format == "stix"
    assert result.added == 1
    assert ws.find_entity_by_value("1.2.3.4") is not None
