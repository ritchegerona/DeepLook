"""MITRE ATT&CK coverage page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.attack_mapping import annotate_entities, list_techniques, map_workspace
from deeplook.gui.components.state import get_workspace

st.title("🎯 MITRE ATT&CK Coverage")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

entities = ws.all_entities()
st.metric("Entities in Workspace", len(entities))

annotate = st.checkbox("Persist technique IDs to entities", value=False, key="attack_annotate")

tab1, tab2 = st.tabs(["Coverage", "Technique Registry"])

with tab1:
    if st.button("Map Coverage", type="primary", key="attack_map"):
        report = annotate_entities(ws, entities) if annotate else map_workspace(ws, entities)

        c1, c2, c3 = st.columns(3)
        c1.metric("Techniques", len(report.techniques))
        c2.metric("Tactics", len(report.tactics))
        c3.metric("Unmapped Entities", len(report.unmapped))

        if report.techniques:
            rows = [
                {
                    "id": u.technique.id,
                    "name": u.technique.name,
                    "tactic": u.technique.tactic,
                    "entities": len(u.entities),
                }
                for u in report.techniques
            ]
            st.dataframe(rows, use_container_width=True, height=450)
            st.caption("Tactics: " + ", ".join(report.tactics))
        else:
            st.info("No ATT&CK techniques mapped. Run an investigation first.")

        if report.unmapped:
            with st.expander(f"Unmapped entities ({len(report.unmapped)})"):
                for value in report.unmapped:
                    st.write(f"• {value}")

with tab2:
    techniques = list_techniques()
    st.caption(f"{len(techniques)} techniques in the DeepLook recon/resource-development registry.")
    st.dataframe(techniques, use_container_width=True, height=450)
