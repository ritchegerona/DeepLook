# DeepLook Plugin Development Guide

How to create custom plugins for the DeepLook OSINT framework.

---

## Plugin Architecture

DeepLook plugins are Python classes that inherit from `OSINTPlugin` and implement the `run()` method. Plugins are auto-discovered from the `deeplook/plugins/` directory and any files in `~/.deeplook/plugins/`.

---

## Creating a Plugin

### Basic Structure

```python
"""My custom OSINT plugin."""

from __future__ import annotations

from deeplook.plugins.base import OSINTPlugin, register_plugin, PluginResult
from deeplook.core.entity import Entity, EntityType
from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.workspace import Workspace


@register_plugin
class MyPlugin(OSINTPlugin):
    name = "my-plugin"
    description = "Description of what this plugin does"
    entity_types = [EntityType.DOMAIN]  # Which entity types this plugin handles
    requires_key = False  # Whether an API key is required
    key_env_var = ""  # Environment variable for API key
    confidence = 0.8  # Base confidence score (0.0-1.0)
    version = "1.0.0"
    tags = ["custom", "example"]

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        """Execute the plugin against a target entity."""
        result = PluginResult()

        # Your investigation logic here
        # ...

        # Add discovered entities
        new_entity = Entity(type=EntityType.IP, value="1.2.3.4")
        new_entity.add_provenance(source=self.name, confidence=0.9)
        workspace.add_entity(new_entity)
        result.add_entity(new_entity)

        # Add relationships
        edge = Edge(
            source_id=entity.id,
            target_id=new_entity.id,
            relationship=RelationshipType.RESOLVES_TO,
            source_plugin=self.name,
        )
        workspace.add_edge(edge)
        result.add_edge(edge)

        return result
```

### Plugin Registration

Use the `@register_plugin` decorator to register your plugin:

```python
@register_plugin
class MyPlugin(OSINTPlugin):
    ...
```

The plugin will be automatically discovered and loaded by DeepLook.

---

## Plugin Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | `str` | Unique plugin identifier (kebab-case) |
| `description` | `str` | Human-readable description |
| `entity_types` | `list[EntityType]` | Entity types this plugin handles |
| `requires_key` | `bool` | Whether an API key is required |
| `key_env_var` | `str` | Environment variable for API key |
| `confidence` | `float` | Base confidence score (0.0-1.0) |
| `version` | `str` | Plugin version |
| `tags` | `list[str]` | Tags for categorization |

---

## Entity Types

Available entity types:

| Type | Description | Example |
|------|-------------|---------|
| `EntityType.DOMAIN` | Domain name | `example.com` |
| `EntityType.IP` | IP address | `8.8.8.8` |
| `EntityType.EMAIL` | Email address | `user@example.com` |
| `EntityType.USERNAME` | Username/handle | `johndoe` |
| `EntityType.PHONE` | Phone number | `+15551234567` |
| `EntityType.HASH` | File hash (MD5/SHA1/SHA256) | `d41d8cd98f00b204` |
| `EntityType.BTC` | Bitcoin wallet address | `1A1zP1eP5QGefi2DMPTf` |
| `EntityType.URL` | URL | `https://example.com` |
| `EntityType.SUBDOMAIN` | Subdomain | `api.example.com` |
| `EntityType.CERT` | TLS certificate | Certificate fingerprint |
| `EntityType.ASN` | Autonomous System Number | `AS15169` |
| `EntityType.ORG` | Organization | `Google LLC` |

---

## Relationship Types

Available relationship types:

| Type | Description | Example |
|------|-------------|---------|
| `RelationshipType.RESOLVES_TO` | Domain resolves to IP | `example.com → 93.184.216.34` |
| `RelationshipType.REVERSE_DNS` | IP reverse DNS | `8.8.8.8 → dns.google` |
| `RelationshipType.REGISTRANT` | Domain registrant | `example.com → admin@example.com` |
| `RelationshipType.MX_RECORD` | MX record | `example.com → mx1.example.com` |
| `RelationshipType.NS_RECORD` | Nameserver | `example.com → ns1.example.com` |
| `RelationshipType.SUBDOMAIN_OF` | Subdomain relationship | `api.example.com → example.com` |
| `RelationshipType.LINKS_TO` | Page links to domain | `page.html → other.com` |
| `RelationshipType.PROFILE_ON` | Username profile on platform | `johndoe → github.com` |
| `RelationshipType.CONTACT_EMAIL` | Contact email | `example.com → admin@example.com` |
| `RelationshipType.HOSTED_ON` | Hosted on infrastructure | `example.com → 93.184.216.34` |
| `RelationshipType.CERT_ISSUED_TO` | Certificate issued to | `cert → example.com` |
| `RelationshipType.ASSOCIATED_WITH` | General association | `IP → Organization` |
| `RelationshipType.REDIRECTS_TO` | HTTP redirect | `a.com → b.com` |
| `RelationshipType.USES_TECH` | Uses technology | `site → WordPress` |
| `RelationshipType.BREACHED_IN` | Found in breach | `email → LinkedIn breach` |
| `RelationshipType.OWNED_BY` | Owned by | `IP → Organization` |
| `RelationshipType.SIMILAR_TO` | Similar to | `domain → similar.com` |
| `RelationshipType.MENTIONED_IN` | Mentioned in | `indicator → report` |

---

## PluginResult

The `PluginResult` class holds the output of a plugin execution:

```python
result = PluginResult()

# Add discovered entities
result.add_entity(entity)

# Add discovered relationships
result.add_edge(edge)

# Add warnings
result.add_warning("Something unexpected happened")

# Access results
print(result.entities)  # list[Entity]
print(result.edges)     # list[Edge]
print(result.warnings)  # list[str]
print(result.metadata)  # dict[str, Any]
```

---

## Error Handling

Plugins should handle errors gracefully:

```python
def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
    result = PluginResult()

    try:
        # Your investigation logic
        response = requests.get(f"https://api.example.com/{entity.value}")
        response.raise_for_status()
        data = response.json()

        # Process data...

    except requests.Timeout:
        result.add_warning(f"Timeout querying {entity.value}")
    except requests.HTTPError as e:
        result.add_warning(f"HTTP error: {e}")
    except Exception as e:
        result.add_warning(f"Unexpected error: {e}")

    return result
```

---

## Using the Cache

Plugins can use the cache to avoid redundant queries:

```python
def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
    result = PluginResult()

    # Check cache first (handled by execute() wrapper)
    # If cached, this method won't be called

    # Your investigation logic
    data = query_api(entity.value)

    result.metadata["api_response"] = data
    return result
```

The cache is automatically managed by the `execute()` wrapper method.

---

## Provenance Tracking

Always track where findings came from:

```python
# Add provenance to entities
entity.add_provenance(
    source=self.name,
    confidence=0.9,
    raw_data={"api_response": data}
)

# Add provenance to edges
edge = Edge(
    source_id=entity.id,
    target_id=target.id,
    relationship=RelationshipType.RESOLVES_TO,
    source_plugin=self.name,
    confidence=0.9,
)
```

---

## Example: Simple DNS Plugin

```python
"""DNS record lookup plugin."""

from __future__ import annotations

import dns.resolver
from deeplook.plugins.base import OSINTPlugin, register_plugin, PluginResult
from deeplook.core.entity import Entity, EntityType
from deeplook.core.edge import Edge, RelationshipType
from deeplook.core.workspace import Workspace


@register_plugin
class SimpleDNS(OSINTPlugin):
    name = "simple-dns"
    description = "Simple DNS A record lookup"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.9

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()

        try:
            answers = dns.resolver.resolve(entity.value, "A")
            for rdata in answers:
                ip_entity = Entity(
                    type=EntityType.IP,
                    value=str(rdata),
                    confidence=95.0,
                )
                ip_entity.add_provenance(source=self.name, confidence=0.95)
                workspace.add_entity(ip_entity)
                result.add_entity(ip_entity)

                edge = Edge(
                    source_id=entity.id,
                    target_id=ip_entity.id,
                    relationship=RelationshipType.RESOLVES_TO,
                    source_plugin=self.name,
                    confidence=0.95,
                )
                workspace.add_edge(edge)
                result.add_edge(edge)

        except dns.resolver.NoAnswer:
            result.add_warning(f"No A records found for {entity.value}")
        except dns.resolver.NXDOMAIN:
            result.add_warning(f"Domain {entity.value} does not exist")

        return result
```

---

## Testing Plugins

Create tests in `tests/test_plugins/`:

```python
"""Tests for my plugin."""

from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace
from deeplook.plugins.my_plugin import MyPlugin


class TestMyPlugin:
    def test_run(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        plugin = MyPlugin()
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        result = plugin.run(entity, ws)

        assert len(result.entities) > 0
        assert len(result.edges) > 0
        ws.close()
```

Run tests:
```bash
pytest tests/test_plugins/test_my_plugin.py -v
```

---

## Plugin Installation

### Built-in Plugins

Place your plugin file in `deeplook/plugins/`:

```bash
cp my_plugin.py deeplook/plugins/
```

### User Plugins

Place your plugin file in `~/.deeplook/plugins/`:

```bash
mkdir -p ~/.deeplook/plugins
cp my_plugin.py ~/.deeplook/plugins/
```

### Verify Installation

```bash
deeplook plugins --action list
deeplook plugins --action info --name my-plugin
```

---

## Best Practices

1. **Use descriptive names**: Plugin names should be kebab-case and descriptive
2. **Track provenance**: Always use `add_provenance()` to track sources
3. **Handle errors gracefully**: Catch exceptions and add warnings
4. **Set appropriate confidence**: Base confidence should reflect source reliability
5. **Use the cache**: Let the framework handle caching via `execute()` wrapper
6. **Write tests**: Test your plugin with mocked network calls
7. **Document your plugin**: Add a description and tags
8. **Follow conventions**: Match the code style of existing plugins
