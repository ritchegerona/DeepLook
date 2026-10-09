"""Watchlist management and change monitoring page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.entity import create_entity
from deeplook.core.watchlist import WatchlistEngine
from deeplook.gui.components.state import get_workspace

st.title("👁️ Watchlist")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

tab1, tab2 = st.tabs(["Watchlist", "Check for Changes"])

with tab1:
    st.subheader("Add Indicator")
    col1, col2 = st.columns([2, 2])
    with col1:
        value = st.text_input("Indicator", placeholder="evil[.]com", key="watch_value")
    with col2:
        tags = st.text_input("Tags (comma-separated)", key="watch_tags")

    if st.button("Add", type="primary", key="watch_add"):
        if not value:
            st.warning("Enter an indicator to watch.")
        else:
            try:
                entity = create_entity(value)
            except ValueError as exc:
                st.error(str(exc))
            else:
                tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
                watch_id = ws.add_watch(entity.type.value, entity.value, tags=tag_list)
                st.success(f"Watching {entity.type.value} '{entity.value}' (id {watch_id})")
                st.rerun()

    st.divider()
    items = ws.list_watch()
    if not items:
        st.info("Watchlist is empty.")
    else:
        for item in items:
            col1, col2 = st.columns([6, 1])
            with col1:
                last_checked = item["last_checked"] or "never"
                st.markdown(f"**#{item['id']}** `{item['type']}` **{item['value']}** · last checked: {last_checked}")
            with col2:
                if st.button("Remove", key=f"watch_remove_{item['id']}"):
                    ws.remove_watch(item["id"])
                    st.rerun()

with tab2:
    if not ws.list_watch():
        st.info("Add indicators to the watchlist first.")
    else:
        st.caption("Re-runs the relevant plugins and diffs results against the previous check.")
        if st.button("Check All", type="primary", key="watch_check"):
            with st.spinner("Checking watchlist..."):
                results = WatchlistEngine(ws).check_all()

            total = sum(len(r.changes) for r in results)
            c1, c2 = st.columns(2)
            c1.metric("Items Checked", len(results))
            c2.metric("Changes", total)

            for result in results:
                st.markdown(f"### {result.item.value}")
                if result.error:
                    st.warning(result.error)
                if result.changes:
                    for change in result.changes:
                        icon = "🟢 +" if change.change == "added" else "🔴 -"
                        st.write(f"{icon} {change.detail}")
                else:
                    st.caption("No changes.")
