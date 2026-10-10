"""Tests for the passive RDAP domain plugin (mocked HTTP)."""

from __future__ import annotations

import responses as responses_mock

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.domain_rdap import DomainRDAPPlugin

_RDAP_BODY = {
    "handle": "EXAMPLE-COM",
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2023-08-14T07:01:38Z"},
    ],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "NS2.EXAMPLE.NET"}],
    "entities": [
        {
            "roles": ["registrar"],
            "handle": "376",
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
        }
    ],
}


@responses_mock.activate
def test_rdap_parses_registrar_events_and_nameservers(tmp_path):
    responses_mock.add(responses_mock.GET, "https://rdap.org/domain/example.com", json=_RDAP_BODY)

    ws = Workspace("rdap", base_dir=tmp_path)
    entity = Entity(type=EntityType.DOMAIN, value="example.com")
    result = DomainRDAPPlugin().run(entity, ws)

    assert entity.metadata["registrar"] == "Example Registrar"
    assert entity.metadata["creation_date"] == "1995-08-14T04:00:00Z"
    assert entity.metadata["name_servers"] == ["ns1.example.net", "ns2.example.net"]
    assert entity.metadata["rdap_status"] == ["client transfer prohibited"]
    assert any(e.type == EntityType.ORG and e.value == "Example Registrar" for e in result.entities)
    assert len(result.edges) == 3  # 2 nameservers + 1 registrar
    ws.close()


@responses_mock.activate
def test_rdap_does_not_clobber_existing_whois_data(tmp_path):
    responses_mock.add(responses_mock.GET, "https://rdap.org/domain/example.com", json=_RDAP_BODY)

    ws = Workspace("rdap-merge", base_dir=tmp_path)
    entity = Entity(type=EntityType.DOMAIN, value="example.com")
    entity.metadata["registrar"] = "Existing Registrar"
    DomainRDAPPlugin().run(entity, ws)

    assert entity.metadata["registrar"] == "Existing Registrar"
    assert entity.metadata["rdap_registrar"] == "Example Registrar"
    ws.close()


@responses_mock.activate
def test_rdap_missing_record_warns(tmp_path):
    responses_mock.add(responses_mock.GET, "https://rdap.org/domain/none.example", status=404)

    ws = Workspace("rdap-404", base_dir=tmp_path)
    entity = Entity(type=EntityType.DOMAIN, value="none.example")
    result = DomainRDAPPlugin().run(entity, ws)

    assert result.entities == []
    assert result.warnings
    ws.close()


@responses_mock.activate
def test_rdap_handles_transport_error(tmp_path):
    responses_mock.add(
        responses_mock.GET,
        "https://rdap.org/domain/down.example",
        body=responses_mock.ConnectionError("boom"),
    )

    ws = Workspace("rdap-err", base_dir=tmp_path)
    result = DomainRDAPPlugin().run(Entity(type=EntityType.DOMAIN, value="down.example"), ws)

    assert result.warnings
    ws.close()
