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
        st.Page("pages/recon/domain.py", title="Domain", icon=":globe_with_meridians:"),
        st.Page("pages/recon/ip.py", title="IP", icon=":round_pushpin:"),
        st.Page("pages/recon/email.py", title="Email", icon=":e-mail:"),
        st.Page("pages/recon/username.py", title="Username", icon=":bust_in_silhouette:"),
        st.Page("pages/recon/phone.py", title="Phone", icon=":iphone:"),
        st.Page("pages/recon/hash.py", title="Hash", icon=":hash:"),
        st.Page("pages/recon/btc.py", title="BTC Wallet", icon=":moneybag:"),
        st.Page("pages/recon/website.py", title="Website", icon=":spider:"),
    ],
    "Analysis": [
        st.Page("pages/analysis/analyze.py", title="Analyze", icon=":microscope:"),
        st.Page("pages/analysis/security.py", title="Security", icon=":shield:"),
        st.Page("pages/analysis/graph.py", title="Graph", icon=":bar_chart:"),
        st.Page("pages/analysis/correlate.py", title="Correlate", icon=":link:"),
    ],
    "Management": [
        st.Page("pages/management/workspace.py", title="Workspace", icon=":card_file_box:"),
        st.Page("pages/management/export.py", title="Export", icon=":outbox_tray:"),
        st.Page("pages/management/plugins.py", title="Plugins", icon=":jigsaw:"),
        st.Page("pages/management/query.py", title="Query", icon=":mag:"),
        st.Page("pages/management/search.py", title="Search", icon=":mag_right:"),
        st.Page("pages/management/diff.py", title="Diff", icon=":clipboard:"),
        st.Page("pages/management/note.py", title="Notes", icon=":memo:"),
        st.Page("pages/management/timeline.py", title="Timeline", icon=":clock3:"),
    ],
    "Bulk": [
        st.Page("pages/bulk/scan.py", title="Scan", icon=":satellite_antenna:"),
    ],
}

pg = st.navigation(pages)
pg.run()
