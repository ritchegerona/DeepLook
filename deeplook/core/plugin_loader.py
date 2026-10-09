"""Auto-discovery and loading of OSINT plugins."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

from deeplook.plugins.base import OSINTPlugin, get_registry


def load_builtin_plugins() -> dict[str, OSINTPlugin]:
    """Load all built-in plugins from the plugins directory."""
    plugins_dir = Path(__file__).parent.parent / "plugins"
    _discover_plugins(plugins_dir)

    registry = get_registry()
    loaded = {}
    for name, cls in registry.items():
        try:
            plugin = cls()
            loaded[name] = plugin
        except Exception:
            pass
    return loaded


def load_user_plugins(user_dir: Path | None = None) -> dict[str, OSINTPlugin]:
    """Load user-installed plugins from ~/.deeplook/plugins/."""
    if user_dir is None:
        user_dir = Path.home() / ".deeplook" / "plugins"
    if not user_dir.exists():
        return {}

    _discover_plugins(user_dir)

    registry = get_registry()
    loaded = {}
    for name, cls in registry.items():
        try:
            plugin = cls()
            loaded[name] = plugin
        except Exception:
            pass
    return loaded


def load_all_plugins() -> dict[str, OSINTPlugin]:
    """Load built-in + user plugins."""
    plugins = load_builtin_plugins()
    plugins.update(load_user_plugins())
    return plugins


def _discover_plugins(directory: Path) -> None:
    """Discover and import all plugin modules in a directory."""
    if not directory.exists():
        return

    for py_file in directory.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        module_name = f"deeplook.plugins.{py_file.stem}"
        if module_name in sys.modules:
            continue
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
        except Exception:
            pass


def get_plugins_for_entity(entity_type: str, plugins: dict[str, OSINTPlugin] | None = None) -> list[OSINTPlugin]:
    """Get all plugins that handle a specific entity type."""
    if plugins is None:
        plugins = load_all_plugins()
    from deeplook.core.entity import EntityType

    try:
        etype = EntityType(entity_type)
    except ValueError:
        return []
    return [p for p in plugins.values() if etype in p.entity_types]


def list_plugins(plugins: dict[str, OSINTPlugin] | None = None) -> list[dict[str, Any]]:
    """List all loaded plugins with their info."""
    if plugins is None:
        plugins = load_all_plugins()
    return [p.info() for p in plugins.values()]
