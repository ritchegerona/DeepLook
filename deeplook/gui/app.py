"""DeepLook GUI — Streamlit entry point with multi-page navigation."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Ensure deeplook is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from deeplook.gui.components.state import (
    get_workspace,
    get_workspace_list,
    init_session_state,
    load_workspace_by_name,
)
from deeplook.gui.components.styling import inject_css

st.set_page_config(
    page_title="DeepLook — OSINT Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_css()
init_session_state()

# ── Sidebar: Workspace Selector ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("# 🔍 DeepLook")
    st.caption("OSINT & Threat Intelligence Dashboard")
    st.divider()

    workspaces = get_workspace_list()
    if workspaces:
        selected = st.selectbox(
            "Workspace",
            workspaces,
            index=workspaces.index(st.session_state.active_workspace_name)
            if st.session_state.active_workspace_name in workspaces
            else 0,
        )
        if selected and selected != st.session_state.active_workspace_name:
            load_workspace_by_name(selected)
    else:
        st.info("No workspaces found.")
        if st.button("Create Default Workspace"):
            from deeplook.core.workspace import Workspace

            Workspace.create("default")
            load_workspace_by_name("default")
            st.rerun()

    ws = get_workspace()
    if ws:
        st.divider()
        st.markdown(f"**Active:** `{st.session_state.active_workspace_name}`")
        entities = ws.all_entities()
        edges = ws.all_edges()
        st.caption(f"{len(entities)} entities · {len(edges)} relationships")

    st.divider()
    st.markdown(
        """
        <div style="font-size: 11px; color: #666;">
        DeepLook v1.0.0<br>
        OSINT & Threat Intelligence
        </div>
        """,
        unsafe_allow_html=True,
    )

# ── Page Navigation ──────────────────────────────────────────────────────────
pages = {
    "Recon": [
        st.Page("pages/recon/domain.py", title="Domain"),
        st.Page("pages/recon/ip.py", title="IP"),
        st.Page("pages/recon/email.py", title="Email"),
        st.Page("pages/recon/username.py", title="Username"),
        st.Page("pages/recon/phone.py", title="Phone"),
        st.Page("pages/recon/hash.py", title="Hash"),
        st.Page("pages/recon/btc.py", title="BTC Wallet"),
        st.Page("pages/recon/website.py", title="Website"),
    ],
    "Analysis": [
        st.Page("pages/analysis/analyze.py", title="Analyze"),
        st.Page("pages/analysis/pivot.py", title="Pivot"),
        st.Page("pages/analysis/attack.py", title="ATT&CK"),
        st.Page("pages/analysis/security.py", title="Security"),
        st.Page("pages/analysis/graph.py", title="Graph"),
        st.Page("pages/analysis/correlate.py", title="Correlate"),
        st.Page("pages/analysis/ai.py", title="AI"),
    ],
    "Management": [
        st.Page("pages/management/workspace.py", title="Workspace"),
        st.Page("pages/management/ingest.py", title="Ingest"),
        st.Page("pages/management/watchlist.py", title="Watchlist"),
        st.Page("pages/management/export.py", title="Export"),
        st.Page("pages/management/plugins.py", title="Plugins"),
        st.Page("pages/management/query.py", title="Query"),
        st.Page("pages/management/search.py", title="Search"),
        st.Page("pages/management/diff.py", title="Diff"),
        st.Page("pages/management/note.py", title="Notes"),
        st.Page("pages/management/timeline.py", title="Timeline"),
    ],
    "Bulk": [
        st.Page("pages/bulk/scan.py", title="Scan"),
    ],
}

pg = st.navigation(pages)
pg.run()
