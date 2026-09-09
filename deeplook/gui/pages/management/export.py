"""Export page."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from deeplook.gui.components.state import get_workspace

st.title("📤 Export Workspace Data")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

entities = ws.all_entities()
edges = ws.all_edges()

st.metric("Entities", len(entities))
st.metric("Relationships", len(edges))

export_format = st.selectbox("Export Format", ["json", "csv", "xlsx", "stix"], key="export_format")
output_path = st.text_input(
    "Output Path", value=f"export-{st.session_state.active_workspace_name}.{export_format}", key="export_path"
)

if st.button("Export", type="primary", key="export_run"):
    with st.spinner(f"Exporting to {export_format}..."):
        try:
            if export_format == "json":
                from deeplook.output.json_export import export_json

                export_json(ws, Path(output_path))
            elif export_format == "csv":
                from deeplook.output.csv_export import export_csv

                export_csv(ws, Path(output_path))
            elif export_format == "xlsx":
                from deeplook.output.excel_export import export_xlsx

                export_xlsx(ws, Path(output_path))
            elif export_format == "stix":
                from deeplook.output.stix_export import export_stix

                export_stix(ws, Path(output_path))

            st.success(f"Exported to {output_path}")
            st.balloons()
        except Exception as e:
            st.error(f"Export failed: {e}")
