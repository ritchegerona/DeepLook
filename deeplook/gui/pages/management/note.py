"""Investigation notes page."""

from __future__ import annotations

import streamlit as st

from deeplook.gui.components.state import get_workspace

st.title("📝 Investigation Notes")

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

tab1, tab2 = st.tabs(["Add Note", "View Notes"])

with tab1:
    st.subheader("Add New Note")
    note_content = st.text_area("Note", placeholder="Enter investigation note...", key="note_content")
    entity_value = st.text_input("Attach to entity (optional)", placeholder="example.com", key="note_entity")

    if st.button("Add Note", type="primary", key="add_note"):
        if note_content:
            entity_id = None
            if entity_value:
                entity = ws.find_entity_by_value(entity_value)
                if entity:
                    entity_id = entity.id
                else:
                    st.warning(f"Entity '{entity_value}' not found. Note will be added globally.")

            ws.add_note(note_content, entity_id=entity_id)
            st.success("Note added!")
            st.rerun()
        else:
            st.warning("Please enter a note.")

with tab2:
    st.subheader("All Notes")
    notes = ws.get_notes()
    if notes:
        for note in notes:
            with st.expander(f"{note.get('created_at', 'Unknown')} — {note.get('content', '')[:50]}..."):
                st.write(note.get("content", ""))
                if note.get("entity_id"):
                    st.caption(f"Attached to entity: {note['entity_id'][:8]}...")
    else:
        st.info("No notes yet.")
