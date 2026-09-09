"""Bulk scanning page."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import streamlit as st

from deeplook.core.entity import create_entity
from deeplook.core.plugin_loader import get_plugins_for_entity, load_all_plugins
from deeplook.gui.components.data import edges_to_df, entities_to_df
from deeplook.gui.components.state import get_workspace

st.title("📡 Bulk Scan")

st.info("Upload a file with targets (one per line) to scan them all.")

uploaded_file = st.file_uploader("Target File", type=["txt", "csv"], key="scan_file")

col1, col2 = st.columns(2)
with col1:
    concurrency = st.slider("Concurrency", 1, 20, 5, key="scan_concurrency")
with col2:
    plugins_to_run = st.multiselect(
        "Plugins (leave empty for auto-detect)",
        [
            "domain-whois",
            "domain-dns",
            "domain-subdomain",
            "ip-geoloc",
            "ip-revdns",
            "ip-ports",
            "email-syntax",
            "email-mx",
            "username-social",
        ],
        default=[],
        key="scan_plugins",
    )

if uploaded_file and st.button("Start Scan", type="primary", key="scan_run"):
    ws = get_workspace()
    if not ws:
        st.error("No workspace selected. Go to Workspace page to create one.")
        st.stop()

    content = uploaded_file.read().decode("utf-8")
    targets = [line.strip() for line in content.splitlines() if line.strip()]

    if not targets:
        st.warning("No targets found in file.")
        st.stop()

    st.info(f"Scanning {len(targets)} targets with concurrency {concurrency}...")

    all_plugins = load_all_plugins()
    all_entities = []
    all_edges = []

    progress = st.progress(0, text="Starting scan...")
    status = st.status("Scanning...", expanded=True)

    def scan_target(target: str):
        entity = create_entity(target)
        ws.add_entity(entity)

        if plugins_to_run:
            matching = [all_plugins[p] for p in plugins_to_run if p in all_plugins]
        else:
            matching = get_plugins_for_entity(entity.type.value)

        results_e = []
        results_ed = []

        for plugin in matching:
            if not plugin.check_key():
                continue
            try:
                result = plugin.execute(entity, ws)
                for e in result.entities:
                    ws.add_entity(e)
                    results_e.append(e)
                for edge in result.edges:
                    ws.add_edge(edge)
                    results_ed.append(edge)
            except Exception:
                pass

        return results_e, results_ed

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(scan_target, t): t for t in targets}
        completed = 0

        for future in as_completed(futures):
            target = futures[future]
            try:
                entities, edges = future.result()
                all_entities.extend(entities)
                all_edges.extend(edges)
            except Exception as e:
                status.update(label=f"Error scanning {target}: {e}", state="running")

            completed += 1
            progress.progress(completed / len(targets), text=f"Scanned {completed}/{len(targets)}")

    status.update(label="Scan complete!", state="complete")
    progress.progress(1.0, text="Done!")

    ws.add_timeline_event("Bulk scan completed", details={"targets": len(targets)})

    st.divider()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Targets Scanned", len(targets))
    with col2:
        st.metric("Entities Found", len(all_entities))
    with col3:
        st.metric("Relationships", len(all_edges))

    tabs = st.tabs(["Entities", "Relationships"])

    with tabs[0]:
        df = entities_to_df(all_entities)
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No entities discovered.")

    with tabs[1]:
        df = edges_to_df(all_edges, all_entities)
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No relationships found.")
