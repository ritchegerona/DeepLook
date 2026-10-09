"""Tests for entity model."""

from deeplook.core.entity import (
    Entity,
    EntityType,
    ProvenanceEntry,
    create_entity,
    detect_entity_type,
)


class TestEntityType:
    def test_detect_ip(self):
        assert detect_entity_type("8.8.8.8") == EntityType.IP

    def test_detect_email(self):
        assert detect_entity_type("user@example.com") == EntityType.EMAIL

    def test_detect_domain(self):
        assert detect_entity_type("example.com") == EntityType.DOMAIN

    def test_detect_btc(self):
        assert detect_entity_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == EntityType.BTC

    def test_detect_md5(self):
        assert detect_entity_type("d41d8cd98f00b204e9800998ecf8427e") == EntityType.HASH

    def test_detect_sha1(self):
        assert detect_entity_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == EntityType.HASH

    def test_detect_sha256(self):
        assert detect_entity_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == EntityType.HASH

    def test_detect_phone(self):
        assert detect_entity_type("+15551234567") == EntityType.PHONE

    def test_detect_unknown(self):
        assert detect_entity_type("not-a-valid-entity") is None


class TestEntity:
    def test_create_entity(self):
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        assert entity.type == EntityType.DOMAIN
        assert entity.value == "example.com"
        assert entity.confidence == 100.0
        assert entity.id

    def test_create_entity_auto_detect(self):
        entity = create_entity("8.8.8.8")
        assert entity.type == EntityType.IP
        assert entity.value == "8.8.8.8"

    def test_add_provenance(self):
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        entity.add_provenance("test-plugin", confidence=0.9)
        assert len(entity.provenance) == 1
        assert entity.provenance[0].source == "test-plugin"

    def test_add_note(self):
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        entity.add_note("test note")
        assert len(entity.notes) == 1
        assert "test note" in entity.notes[0]

    def test_add_tag(self):
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        entity.add_tag("suspicious")
        assert "suspicious" in entity.tags
        entity.add_tag("suspicious")
        assert entity.tags.count("suspicious") == 1

    def test_to_dict(self):
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        d = entity.to_dict()
        assert d["type"] == "domain"
        assert d["value"] == "example.com"
        assert "id" in d
        assert "first_seen" in d

    def test_from_dict(self):
        d = {
            "id": "test-id",
            "type": "domain",
            "value": "example.com",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
            "confidence": 95.0,
            "provenance": [],
            "notes": [],
            "tags": [],
            "metadata": {},
        }
        entity = Entity.from_dict(d)
        assert entity.id == "test-id"
        assert entity.type == EntityType.DOMAIN

    def test_equality(self):
        e1 = Entity(type=EntityType.DOMAIN, value="Example.com")
        e2 = Entity(type=EntityType.DOMAIN, value="example.com")
        assert e1 == e2

    def test_hash(self):
        e1 = Entity(type=EntityType.DOMAIN, value="example.com")
        e2 = Entity(type=EntityType.DOMAIN, value="example.com")
        assert hash(e1) == hash(e2)


class TestProvenance:
    def test_provenance_entry(self):
        entry = ProvenanceEntry(source="test", confidence=0.8)
        assert entry.source == "test"
        assert entry.confidence == 0.8
