"""Phone investigation page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.entity import create_entity
from deeplook.core.plugin_loader import load_all_plugins
from deeplook.gui.components.data import edges_to_df, entities_to_df
from deeplook.gui.components.state import get_workspace

st.title("📱 Phone Investigation")

target = st.text_input("Phone Number", placeholder="+15551234567", key="phone_target")

col1, col2 = st.columns([1, 3])
with col1:
    run_btn = st.button("Investigate", type="primary", key="phone_run")
with col2:
    plugins_to_run = st.multiselect(
        "Plugins",
        ["phone-lookup"],
        default=["phone-lookup"],
        key="phone_plugins",
    )

if run_btn and target:
    ws = get_workspace()
    if not ws:
        st.error("No workspace selected. Go to Workspace page to create one.")
        st.stop()

    entity = create_entity(target)
    ws.add_entity(entity)
    all_plugins = load_all_plugins()

    progress = st.progress(0, text="Starting phone lookup...")
    status = st.status("Running plugins...", expanded=True)

    results_entities = []
    results_edges = []

    for i, pname in enumerate(plugins_to_run):
        if pname not in all_plugins:
            continue
        plugin = all_plugins[pname]
        if not plugin.check_key():
            status.update(label=f"⏭️ Skipping {pname} (API key required)", state="running")
            continue

        status.update(label=f"Running {pname}...", state="running")
        progress.progress((i + 1) / len(plugins_to_run), text=f"Running {pname}...")

        result = plugin.execute(entity, ws)

        for e in result.entities:
            ws.add_entity(e)
            results_entities.append(e)
        for edge in result.edges:
            ws.add_edge(edge)
            results_edges.append(edge)

    status.update(label="Investigation complete!", state="complete")
    progress.progress(1.0, text="Done!")

    ws.add_timeline_event("Phone investigation completed", target=target)

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
    st.warning("Please enter a phone number target.")
