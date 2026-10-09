"""IOC feed ingestion page."""

from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

from deeplook.core.ingest import ingest_file
from deeplook.gui.components.state import get_workspace

st.title("📥 IOC Feed Ingestion")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

st.caption(
    "Ingest plain/defanged text, CSV, STIX 2.1 bundles, or MISP event JSON. Indicators are refanged and deduplicated."
)

uploaded = st.file_uploader("Feed file", type=["txt", "csv", "json", "stix", "misp"], key="ingest_file")

col1, col2 = st.columns(2)
with col1:
    fmt = st.selectbox("Format", ["auto", "text", "csv", "stix", "misp"], key="ingest_format")
with col2:
    tags = st.text_input("Tags (comma-separated)", key="ingest_tags")

if st.button("Ingest", type="primary", key="ingest_run"):
    if not uploaded:
        st.warning("Upload a feed file first.")
        st.stop()

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    suffix = Path(uploaded.name).suffix or ".txt"

    with tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False) as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = Path(tmp.name)

    try:
        result = ingest_file(ws, tmp_path, fmt=fmt, tags=tag_list, source_name=uploaded.name)
    finally:
        tmp_path.unlink(missing_ok=True)

    c1, c2, c3 = st.columns(3)
    c1.metric("Added", result.added)
    c2.metric("Skipped", result.skipped)
    c3.metric("Total", result.total)

    if result.samples:
        st.subheader("Ingested Indicators")
        st.dataframe(result.samples, use_container_width=True, height=350)

    if result.errors:
        with st.expander(f"Warnings ({len(result.errors)})"):
            for error in result.errors:
                st.write(f"• {error}")
