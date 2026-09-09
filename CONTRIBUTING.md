# Contributing to DeepLook

Thank you for your interest in contributing to DeepLook! This document provides guidelines and information for contributors.

---

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- pip or poetry

### Setup

```bash
git clone https://github.com/your-username/DeepLook.git
cd DeepLook
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Verify Setup

```bash
pytest tests/ -v
ruff check .
deeplook --help
```

---

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
```

Use descriptive branch names:
- `feature/add-new-plugin`
- `fix/resolve-dns-timeout`
- `docs/update-readme`

### 2. Make Changes

- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Run Tests

```bash
pytest tests/ -v
ruff check .
ruff format .
```

### 4. Commit Changes

Use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat: add new plugin for XYZ"
git commit -m "fix: handle timeout in DNS lookup"
git commit -m "docs: update CTIA module mapping"
```

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Create a Pull Request with:
- Clear description of changes
- Reference to related issues
- Test results

---

## Code Style

### Python

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use `ruff` for linting and formatting

### Imports

```python
# Standard library
from __future__ import annotations

import json
from pathlib import Path

# Third-party
import requests
from rich.console import Console

# Local
from deeplook.core.entity import Entity, EntityType
```

### Naming

- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Plugin names: `kebab-case`

---

## Plugin Development

See [docs/PLUGINS.md](docs/PLUGINS.md) for the complete plugin development guide.

### Quick Start

```python
from deeplook.plugins.base import OSINTPlugin, register_plugin, PluginResult
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace


@register_plugin
class MyPlugin(OSINTPlugin):
    name = "my-plugin"
    description = "Description of my plugin"
    entity_types = [EntityType.DOMAIN]
    requires_key = False
    confidence = 0.8

    def run(self, entity: Entity, workspace: Workspace) -> PluginResult:
        result = PluginResult()
        # Your logic here
        return result
```

---

## Testing

### Test Structure

```
tests/
├── test_core/           # Core module tests
│   ├── test_entity.py
│   ├── test_edge.py
│   ├── test_graph.py
│   └── test_workspace.py
├── test_plugins/        # Plugin tests
│   └── test_email.py
└── test_output/         # Output formatter tests
    └── __init__.py
```

### Writing Tests

```python
import pytest
from deeplook.core.entity import Entity, EntityType
from deeplook.core.workspace import Workspace


class TestMyFeature:
    def test_something(self, tmp_path):
        ws = Workspace("test-ws", base_dir=tmp_path)
        entity = Entity(type=EntityType.DOMAIN, value="example.com")
        ws.add_entity(entity)
        assert ws.get_entity(entity.id) is not None
        ws.close()
```

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/test_core/test_entity.py -v

# With coverage
pytest tests/ --cov=deeplook
```

---

## Documentation

### Updating Documentation

- `README.md` — Project overview and quick start
- `docs/USAGE.md` — Complete CLI reference
- `docs/CTIA.md` — CTIA module mapping
- `docs/PLUGINS.md` — Plugin development guide

### Building Docs

Documentation is in Markdown format. No build step required.

---

## Issues

### Reporting Bugs

When reporting bugs, please include:

1. DeepLook version (`deeplook version`)
2. Python version (`python3 --version`)
3. Steps to reproduce
4. Expected behavior
5. Actual behavior
6. Error output (if any)

### Suggesting Features

When suggesting features, please include:

1. Use case description
2. Proposed solution
3. Alternatives considered
4. Additional context

---

## Pull Requests

### PR Checklist

- [ ] Tests pass (`pytest tests/ -v`)
- [ ] Lint passes (`ruff check .`)
- [ ] Code is formatted (`ruff format .`)
- [ ] Documentation is updated
- [ ] Commit messages follow Conventional Commits

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing

Describe tests added/updated.

## Checklist

- [ ] Tests pass
- [ ] Lint passes
- [ ] Documentation updated
```

---

## License

By contributing to DeepLook, you agree that your contributions will be licensed under the MIT License.

---

## Questions?

If you have questions about contributing, please open an issue or reach out to the maintainers.
