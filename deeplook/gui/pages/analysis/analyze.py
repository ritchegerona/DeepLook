"""Auto-detect and analyze target page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.entity import create_entity
from deeplook.core.plugin_loader import get_plugins_for_entity, load_all_plugins
from deeplook.gui.components.data import edges_to_df, entities_to_df

st.title("🔬 Auto-Analyze Target")

target = st.text_input(
    "Target",
    placeholder="Enter any indicator: domain, IP, email, username, hash, BTC...",
    key="analyze_target",
)

col1, col2, col3 = st.columns([1, 2, 2])
with col1:
    run_btn = st.button("Analyze", type="primary", key="analyze_run")
with col2:
    workspace_name = st.text_input("Workspace", value="default", key="analyze_workspace")
with col3:
    no_cache = st.checkbox("Skip cache", key="analyze_no_cache")

if run_btn and target:
    from deeplook.core.workspace import Workspace

    ws = Workspace(workspace_name)
    entity = create_entity(target)
    ws.add_entity(entity)

    all_plugins = load_all_plugins()
    matching = get_plugins_for_entity(entity.type.value)

    st.info(f"Detected **{entity.type.value}** — running {len(matching)} plugins")

    progress = st.progress(0, text="Starting analysis...")
    status = st.status("Running plugins...", expanded=True)

    results_entities = []
    results_edges = []

    for i, plugin in enumerate(matching):
        if not plugin.check_key():
            status.update(label=f"⏭️ Skipping {plugin.name} (API key required)", state="running")
            continue

        status.update(label=f"Running {plugin.name}...", state="running")
        progress.progress((i + 1) / len(matching), text=f"Running {plugin.name}...")

        result = plugin.execute(entity, ws)

        for e in result.entities:
            ws.add_entity(e)
            results_entities.append(e)
        for edge in result.edges:
            ws.add_edge(edge)
            results_edges.append(edge)

    status.update(label="Analysis complete!", state="complete")
    progress.progress(1.0, text="Done!")

    ws.add_timeline_event("Auto-analysis completed", target=target)

    st.divider()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Entities Found", len(results_entities))
    with col2:
        st.metric("Relationships", len(results_edges))
    with col3:
        st.metric("Plugins Run", len(matching))

    st.divider()
    st.subheader("Results")

    tabs = st.tabs(["Entities", "Relationships"])

    with tabs[0]:
        df = entities_to_df(results_entities)
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No entities discovered.")

    with tabs[1]:
        df = edges_to_df(results_edges, results_entities)
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No relationships found.")

elif run_btn:
    st.warning("Please enter a target to analyze.")
