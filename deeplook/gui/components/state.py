"""Session state management for DeepLook GUI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import streamlit as st

if TYPE_CHECKING:
    from deeplook.core.workspace import Workspace


def init_session_state() -> None:
    """Initialize session state variables."""
    if "workspace" not in st.session_state:
        st.session_state.workspace = None
    if "active_workspace_name" not in st.session_state:
        st.session_state.active_workspace_name = None
    if "current_entities" not in st.session_state:
        st.session_state.current_entities = []
    if "current_edges" not in st.session_state:
        st.session_state.current_edges = []
    if "last_scan_result" not in st.session_state:
        st.session_state.last_scan_result = None


def get_workspace() -> Workspace | None:
    """Get the current workspace from session state."""
    return st.session_state.workspace


def set_workspace(workspace: Workspace, name: str) -> None:
    """Set the current workspace in session state."""
    st.session_state.workspace = workspace
    st.session_state.active_workspace_name = name


def load_workspace_by_name(name: str) -> Workspace:
    """Load a workspace by name and set it in session state."""
    from deeplook.core.workspace import Workspace

    workspace = Workspace(name)
    set_workspace(workspace, name)
    return workspace


def get_workspace_list() -> list[str]:
    """Get list of available workspace names."""
    from deeplook.core.workspace import Workspace

    return Workspace.list_workspaces()
