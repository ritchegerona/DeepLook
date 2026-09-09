"""Workspace search page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.state import get_workspace

st.title("🔍 Search Workspace")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

query = st.text_input("Search", placeholder="Search entities, edges, notes...", key="search_input")

if st.button("Search", type="primary", key="search_run") and query:
    with st.spinner("Searching..."):
        results = ws.search(query)

    st.divider()

    if results.get("entities"):
        st.subheader(f"Entities ({len(results['entities'])})")
        for entity in results["entities"]:
            st.write(f"• **{entity.type.value}:** {entity.value} (confidence: {entity.confidence:.0f}%)")

    if results.get("edges"):
        st.subheader(f"Relationships ({len(results['edges'])})")
        for edge in results["edges"]:
            st.write(f"• {edge.relationship.value} (confidence: {edge.confidence:.0f}%)")

    if results.get("notes"):
        st.subheader(f"Notes ({len(results['notes'])})")
        for note in results["notes"]:
            st.write(f"• {note.get('created_at', '')} — {note.get('content', '')}")

    if not any(results.values()):
        st.info("No results found.")
