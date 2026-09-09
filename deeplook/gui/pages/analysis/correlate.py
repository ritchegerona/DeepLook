"""Cross-target correlation page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.state import get_workspace

st.title("🔗 Cross-Target Correlation")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

entities = ws.all_entities()
edges = ws.all_edges()

if len(entities) < 2:
    st.info("Need at least 2 entities for correlation. Run multiple investigations first.")
    st.stop()

st.metric("Entities in Workspace", len(entities))
st.metric("Relationships", len(edges))

if st.button("Run Correlation", type="primary", key="correlate_run"):
    from deeplook.output.correlation import correlate

    with st.spinner("Running correlation analysis..."):
        result = correlate(ws)

    st.divider()
    st.subheader("Correlation Results")

    if isinstance(result, dict):
        for key, value in result.items():
            with st.expander(f"**{key}**", expanded=True):
                if isinstance(value, list):
                    for item in value:
                        st.write(f"• {item}")
                elif isinstance(value, dict):
                    st.json(value)
                else:
                    st.write(value)
    elif isinstance(result, str):
        st.markdown(result)
    else:
        st.json(result)
