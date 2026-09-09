"""Snapshot comparison page."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

st.title("📋 Snapshot Diff")

col1, col2 = st.columns(2)
with col1:
    file1 = st.text_input("Snapshot 1", placeholder="scan1.json", key="diff_file1")
with col2:
    file2 = st.text_input("Snapshot 2", placeholder="scan2.json", key="diff_file2")

if st.button("Compare", type="primary", key="diff_run") and file1 and file2:
    try:
        data1 = json.loads(Path(file1).read_text())
        data2 = json.loads(Path(file2).read_text())

        entities1 = {e.get("value") for e in data1.get("entities", [])}
        entities2 = {e.get("value") for e in data2.get("entities", [])}

        added = entities2 - entities1
        removed = entities1 - entities2
        common = entities1 & entities2

        st.divider()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Added", len(added))
        with col2:
            st.metric("Removed", len(removed))
        with col3:
            st.metric("Common", len(common))

        if added:
            st.subheader("Added")
            for v in sorted(added):
                st.success(f"+ {v}")

        if removed:
            st.subheader("Removed")
            for v in sorted(removed):
                st.error(f"- {v}")

        if common:
            st.subheader("Common")
            for v in sorted(common):
                st.write(f"= {v}")

    except Exception as e:
        st.error(f"Error comparing snapshots: {e}")
