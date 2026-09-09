"""Workspace management page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.state import get_workspace_list, load_workspace_by_name

st.title("📁 Workspace Management")

tab1, tab2, tab3 = st.tabs(["List", "Create", "Delete"])

with tab1:
    st.subheader("Available Workspaces")
    workspaces = get_workspace_list()
    if workspaces:
        for ws_name in workspaces:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**{ws_name}**")
            with col2:
                if st.button("Open", key=f"open_{ws_name}"):
                    load_workspace_by_name(ws_name)
                    st.success(f"Switched to workspace: {ws_name}")
                    st.rerun()
    else:
        st.info("No workspaces found. Create one below.")

with tab2:
    st.subheader("Create New Workspace")
    new_name = st.text_input("Workspace Name", key="new_ws_name")
    if st.button("Create", type="primary", key="create_ws"):
        if new_name:
            from deeplook.core.workspace import Workspace

            Workspace.create(new_name)
            load_workspace_by_name(new_name)
            st.success(f"Created and switched to workspace: {new_name}")
            st.rerun()
        else:
            st.warning("Please enter a workspace name.")

with tab3:
    st.subheader("Delete Workspace")
    workspaces = get_workspace_list()
    if workspaces:
        ws_to_delete = st.selectbox("Select workspace to delete", workspaces, key="delete_ws_select")
        if st.button("Delete", type="primary", key="delete_ws"):
            import os
            from pathlib import Path

            ws_path = Path.home() / ".deeplook" / "workspaces" / f"{ws_to_delete}.db"
            if ws_path.exists():
                os.remove(ws_path)
                st.success(f"Deleted workspace: {ws_to_delete}")
                st.rerun()
            else:
                st.error("Workspace file not found.")
    else:
        st.info("No workspaces to delete.")
