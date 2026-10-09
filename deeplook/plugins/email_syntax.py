from __future__ import annotations

import re

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "temp-mail.org",
    "fakeinbox.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "dispostable.com",
    "yopmail.com",
    "yopmail.fr",
    "trashmail.com",
    "maildrop.cc",
    "mailnesia.com",
    "tempail.com",
    "tempr.email",
    "discard.email",
    "discardmail.com",
    "discardmail.de",
    "mohmal.com",
    "getnada.com",
    "emailondeck.com",
    "33mail.com",
    "mytemp.email",
    "burnermail.io",
    "harakirimail.com",
    "tmail.io",
    "tmpmail.net",
    "tmpmail.org",
}


@register_plugin
class EmailSyntax(OSINTPlugin):
    name = "email-syntax"
    description = "Email syntax validation and disposable domain detection"
    entity_types = [EntityType.EMAIL]
    tags = ["passive", "email", "validation"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        try:
            email = entity.value.strip().lower()
            is_valid = bool(EMAIL_REGEX.match(email))

            entity.metadata["valid_syntax"] = is_valid

            if is_valid:
                domain_part = email.split("@", 1)[1]
                entity.metadata["domain"] = domain_part
                entity.metadata["local_part"] = email.split("@", 1)[0]
                entity.metadata["is_disposable"] = domain_part in DISPOSABLE_DOMAINS

                domain_entity = Entity(type=EntityType.DOMAIN, value=domain_part, confidence=95.0)
                domain_entity.add_provenance(source=self.name, confidence=0.95)
                workspace.add_entity(domain_entity)
                result.add_entity(domain_entity)

                contact_edge = Edge(
                    source_id=entity.id,
                    target_id=domain_entity.id,
                    relationship=RelationshipType.CONTACT_EMAIL,
                    source_plugin=self.name,
                    confidence=95.0,
                )
                workspace.add_edge(contact_edge)
                result.add_edge(contact_edge)

                if entity.metadata["is_disposable"]:
                    entity.add_tag("disposable-email")
                    domain_entity.add_tag("disposable-email")
            else:
                entity.add_tag("invalid-email")
                entity.metadata["is_disposable"] = False

            entity.add_provenance(source=self.name, confidence=1.0, raw_data={"email": email, "valid": is_valid})
            workspace.add_entity(entity)
            result.add_entity(entity)

        except Exception as e:
            result.add_warning(f"Email syntax validation failed for {entity.value}: {e}")
            entity.metadata["syntax_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)

        return result
