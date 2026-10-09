"""Recursive auto-pivot page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.pivot import PivotEngine
from deeplook.gui.components.state import get_workspace

st.title("🕸️ Auto-Pivot")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

st.caption("Breadth-first expansion: repeatedly runs the relevant plugins on each newly discovered entity.")

col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    target = st.text_input("Seed indicator", placeholder="example.com", key="pivot_target")
with col2:
    max_depth = st.slider("Max depth", 0, 4, 2, key="pivot_depth")
with col3:
    max_entities = st.slider("Max entities", 5, 200, 50, step=5, key="pivot_max")

if st.button("Run Pivot", type="primary", key="pivot_run"):
    if not target:
        st.warning("Enter a seed indicator.")
        st.stop()

    with st.spinner("Pivoting..."):
        try:
            engine = PivotEngine(ws, max_depth=max_depth, max_entities=max_entities)
            result = engine.pivot(target)
        except ValueError as exc:
            st.error(str(exc))
            st.stop()

    st.divider()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Entities Discovered", result.discovered)
    c2.metric("New Entities", result.entities_added)
    c3.metric("Relationships", result.edges_added)
    c4.metric("Plugins Run", result.plugins_run)

    if result.truncated:
        st.warning("Entity budget reached — increase max entities for deeper coverage.")

    if result.nodes:
        rows = [n.to_dict() for n in sorted(result.nodes, key=lambda n: (n.depth, n.type, n.value))]
        st.dataframe(rows, use_container_width=True, height=400)
    else:
        st.info("No entities discovered.")

    if result.errors:
        with st.expander(f"Warnings ({len(result.errors)})"):
            for error in result.errors:
                st.write(f"• {error}")
