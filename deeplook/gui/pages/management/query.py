"""Natural language query page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.state import get_workspace

st.title("🔎 Natural Language Query")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

query = st.text_input("Query", placeholder="Find all domains linked to this IP...", key="query_input")

if st.button("Search", type="primary", key="query_run") and query:
    with st.spinner("Searching..."):
        results = ws.search(query)

    st.divider()

    if results.get("entities"):
        st.subheader(f"Entities ({len(results['entities'])})")
        for entity in results["entities"]:
            st.write(f"• **{entity.type.value}:** {entity.value}")

    if results.get("edges"):
        st.subheader(f"Relationships ({len(results['edges'])})")
        for edge in results["edges"]:
            st.write(f"• {edge.source_id[:8]} → {edge.target_id[:8]} ({edge.relationship.value})")

    if results.get("notes"):
        st.subheader(f"Notes ({len(results['notes'])})")
        for note in results["notes"]:
            st.write(f"• {note.get('content', '')}")

    if not any(results.values()):
        st.info("No results found.")
