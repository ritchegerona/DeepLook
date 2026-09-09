"""Investigation timeline page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.charts import render_timeline_event
from deeplook.gui.components.data import timeline_to_df
from deeplook.gui.components.state import get_workspace

st.title("⏰ Investigation Timeline")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

events = ws.get_timeline()

if events:
    st.metric("Total Events", len(events))

    # Render timeline
    for event in reversed(events):
        render_timeline_event(event)

    # Also show as table
    with st.expander("Timeline Table"):
        df = timeline_to_df(events)
        if not df.empty:
            st.dataframe(df, use_container_width=True, height=400)
else:
    st.info("No timeline events yet. Run an investigation to generate events.")
