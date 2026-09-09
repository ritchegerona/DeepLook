"""Optional AI/LLM integration for analysis and reporting."""

from __future__ import annotations

import json
import os
from typing import Any

import requests

from deeplook.core.workspace import Workspace


class AIEngine:
    """Optional LLM-powered analysis engine."""

    def __init__(self) -> None:
        self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.provider = "openai" if os.environ.get("OPENAI_API_KEY") else "anthropic"
        self.available = bool(self.api_key)

    def _call_openai(self, prompt: str, max_tokens: int = 2000) -> str | None:
        try:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            return None

    def _call_anthropic(self, prompt: str, max_tokens: int = 2000) -> str | None:
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]
        except Exception:
            return None

    def _call(self, prompt: str, max_tokens: int = 2000) -> str | None:
        if not self.available:
            return None
        if self.provider == "openai":
            return self._call_openai(prompt, max_tokens)
        return self._call_anthropic(prompt, max_tokens)

    def summarize(self, workspace: Workspace) -> str:
        data = self._workspace_summary(workspace)
        prompt = f"""Analyze this OSINT investigation data and provide a concise summary.
Focus on key findings, suspicious indicators, and recommendations for further investigation.

Data:
{json.dumps(data, indent=2, default=str)}

Provide a structured summary with:
1. Key Findings
2. Suspicious Indicators
3. Recommended Next Steps
4. Risk Assessment"""
        result = self._call(prompt)
        if result:
            return result
        msg = "AI analysis unavailable. Set OPENAI_API_KEY or "
        msg += "ANTHROPIC_API_KEY environment variable."
        return msg

    def suggest_pivots(self, workspace: Workspace) -> str:
        data = self._workspace_summary(workspace)
        prompt = (
            "Based on this OSINT investigation data, suggest the most "
            "valuable next investigation steps.\n\n"
            f"Data:\n{json.dumps(data, indent=2, default=str)}\n\n"
            "Suggest 3-5 specific pivot points with reasoning:\n"
            "1. Which entity to investigate next and why\n"
            "2. What additional data sources to query\n"
            "3. What correlations to explore"
        )
        result = self._call(prompt)
        return (
            result or "AI pivot suggestions unavailable. Set OPENAI_API_KEY or ANTHROPIC_API_KEY."
        )

    def generate_report(self, workspace: Workspace) -> str:
        data = self._workspace_summary(workspace)
        prompt = f"""Generate a professional OSINT investigation report draft based on this data.

Data:
{json.dumps(data, indent=2, default=str)}

Format the report as:
# Investigation Report
## Executive Summary
## Methodology
## Findings
## Indicators of Compromise (IOCs)
## Recommendations
## Appendix: Raw Data Summary"""
        result = self._call(prompt, max_tokens=4000)
        return (
            result or "AI report generation unavailable. Set OPENAI_API_KEY or ANTHROPIC_API_KEY."
        )

    def natural_query(self, workspace: Workspace, question: str) -> str:
        data = self._workspace_summary(workspace)
        prompt = f"""Answer this question about the OSINT investigation data.

Question: {question}

Data:
{json.dumps(data, indent=2, default=str)}

Provide a clear, factual answer based on the data above."""
        result = self._call(prompt)
        return result or "AI query unavailable. Set OPENAI_API_KEY or ANTHROPIC_API_KEY."

    def _workspace_summary(self, workspace: Workspace) -> dict[str, Any]:
        entities = workspace.all_entities()
        edges = workspace.all_edges()
        notes = workspace.get_notes()
        timeline = workspace.get_timeline()

        entity_summary = {}
        for e in entities:
            etype = e.type.value
            if etype not in entity_summary:
                entity_summary[etype] = []
            entity_summary[etype].append(
                {
                    "value": e.value,
                    "confidence": e.confidence,
                    "metadata": e.metadata,
                }
            )

        return {
            "entity_count": len(entities),
            "edge_count": len(edges),
            "entities_by_type": entity_summary,
            "relationships": [
                {"from": e.source_id, "to": e.target_id, "type": e.relationship.value}
                for e in edges[:50]
            ],
            "notes": [n["content"] for n in notes],
            "timeline": [t["event"] for t in timeline[-20:]],
        }
