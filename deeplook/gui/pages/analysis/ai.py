"""AI-powered analysis page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.ai_engine import AIEngine
from deeplook.gui.components.state import get_workspace

st.title("🤖 AI Analysis")

engine = AIEngine()
if not engine.available:
    st.warning("AI features require an API key. Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` and restart.")
    st.stop()

ws = get_workspace()
if not ws:
    st.info("No workspace selected. Go to Workspace page to create one.")
    st.stop()

st.caption(f"Provider: `{engine.provider}`")

tab1, tab2 = st.tabs(["Analyze", "Query"])

with tab1:
    action = st.selectbox(
        "Action",
        ["Summarize findings", "Suggest pivots", "Generate report"],
        key="ai_action",
    )

    if st.button("Run", type="primary", key="ai_run"):
        with st.spinner("Consulting the model..."):
            if action == "Summarize findings":
                result = engine.summarize(ws)
            elif action == "Suggest pivots":
                result = engine.suggest_pivots(ws)
            else:
                result = engine.generate_report(ws)

        st.markdown(result)
        st.download_button("Download result", result, file_name="ai-output.md", key="ai_download")

with tab2:
    question = st.text_input("Question", placeholder="Which indicators share infrastructure?", key="ai_question")
    if st.button("Ask", type="primary", key="ai_ask"):
        if not question:
            st.warning("Enter a question.")
        else:
            with st.spinner("Thinking..."):
                st.markdown(engine.natural_query(ws, question))
