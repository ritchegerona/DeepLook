"""Plugins listing page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.plugin_loader import load_all_plugins

st.title("🧩 Installed Plugins")

all_plugins = load_all_plugins()

st.metric("Total Plugins", len(all_plugins))

search = st.text_input("Search plugins", key="plugin_search")

filtered = {}
for name, plugin in all_plugins.items():
    if search and search.lower() not in name.lower():
        continue
    filtered[name] = plugin

if filtered:
    for name, plugin in sorted(filtered.items()):
        with st.expander(f"**{name}** — {plugin.description}", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Entity Types:** {', '.join(e.value for e in plugin.entity_types)}")
                st.write(f"**Requires Key:** {'Yes' if plugin.requires_key else 'No'}")
                if plugin.requires_key and plugin.key_env_var:
                    st.write(f"**Key Env Var:** `{plugin.key_env_var}`")
            with col2:
                st.write(f"**Confidence:** {plugin.confidence:.0%}")
                st.write(f"**Version:** {plugin.version}")
                st.write(f"**Tags:** {', '.join(plugin.tags) if plugin.tags else 'None'}")
else:
    st.info("No plugins found matching search.")
