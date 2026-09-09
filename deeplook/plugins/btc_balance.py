from __future__ import annotations

import requests

from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.base import OSINTPlugin, PluginResult, register_plugin


@register_plugin
class BTCBalancePlugin(OSINTPlugin):
    name = "btc-balance"
    description = "Bitcoin wallet balance and transaction check"
    entity_types = [EntityType.BTC]
    requires_key = False
    confidence = 0.8
    tags = ["btc", "bitcoin", "balance", "blockchain"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            url = f"https://blockchain.info/rawaddr/{entity.value}?limit=5"
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            entity.metadata["balance"] = data.get("final_balance", 0)
            entity.metadata["total_received"] = data.get("total_received", 0)
            entity.metadata["total_sent"] = data.get("total_sent", 0)
            entity.metadata["n_tx"] = data.get("n_tx", 0)
            entity.metadata["unconfirmed_balance"] = data.get("unconfirmed_balance", 0)

            entity.add_provenance(
                source="blockchain.info",
                confidence=0.8,
                raw_data={
                    "balance": data.get("final_balance", 0),
                    "n_tx": data.get("n_tx", 0),
                },
            )
            workspace.add_entity(entity)
            result.add_entity(entity)

            seen_addresses: set[str] = set()
            for tx in data.get("txs", []):
                for inp in tx.get("inputs", []):
                    addr = inp.get("prev_out", {}).get("addr", "")
                    if addr and addr != entity.value and addr not in seen_addresses:
                        seen_addresses.add(addr)
                        addr_entity = Entity(type=EntityType.DOMAIN, value=addr)
                        addr_entity.add_provenance(
                            source="blockchain.info",
                            confidence=0.7,
                        )
                        workspace.add_entity(addr_entity)
                        result.add_entity(addr_entity)

                        edge = Edge(
                            source_id=entity.id,
                            target_id=addr_entity.id,
                            relationship=RelationshipType.ASSOCIATED_WITH,
                            source_plugin=self.name,
                            confidence=0.7,
                        )
                        workspace.add_edge(edge)
                        result.add_edge(edge)

                for outp in tx.get("out", []):
                    addr = outp.get("addr", "")
                    if addr and addr != entity.value and addr not in seen_addresses:
                        seen_addresses.add(addr)
                        addr_entity = Entity(type=EntityType.DOMAIN, value=addr)
                        addr_entity.add_provenance(
                            source="blockchain.info",
                            confidence=0.7,
                        )
                        workspace.add_entity(addr_entity)
                        result.add_entity(addr_entity)

                        edge = Edge(
                            source_id=entity.id,
                            target_id=addr_entity.id,
                            relationship=RelationshipType.ASSOCIATED_WITH,
                            source_plugin=self.name,
                            confidence=0.7,
                        )
                        workspace.add_edge(edge)
                        result.add_edge(edge)

            result.raw_data = data
        except requests.RequestException as e:
            result.add_warning(f"Blockchain.info request failed for {entity.value}: {e}")
            entity.metadata["btc_error"] = str(e)
            workspace.add_entity(entity)
            result.add_entity(entity)
        except Exception as e:
            result.add_warning(f"BTC balance check failed for {entity.value}: {e}")

        return result
