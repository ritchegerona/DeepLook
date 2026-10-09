"""Reusable chart and visualization components for DeepLook GUI."""

from __future__ import annotations

from typing import Any

import streamlit as st


def render_security_score(score: int, risk_level: str) -> None:
    """Render a security score gauge."""
    if score >= 80:
        color = "#22c55e"
        emoji = "🟢"
    elif score >= 60:
        color = "#eab308"
        emoji = "🟡"
    elif score >= 40:
        color = "#f97316"
        emoji = "🟠"
    else:
        color = "#ef4444"
        emoji = "🔴"

    st.markdown(
        f"""
        <div style="text-align: center; padding: 20px;">
            <div style="font-size: 64px; font-weight: bold; color: {color};">{score}</div>
            <div style="font-size: 18px; color: {color};">{emoji} {risk_level.upper()}</div>
            <div style="font-size: 12px; color: #888;">out of 100</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_category_scores(categories: list[dict[str, Any]]) -> None:
    """Render category score bars."""
    for cat in categories:
        name = cat["name"]
        score = cat["score"]
        weight = cat["weight"]
        if score >= 80:
            color = "#22c55e"
        elif score >= 60:
            color = "#eab308"
        elif score >= 40:
            color = "#f97316"
        else:
            color = "#ef4444"

        st.markdown(
            f"""
            <div style="margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="font-size: 14px;">{name}</span>
                    <span style="font-size: 14px; color: {color};">{score}/100 (weight: {weight:.0%})</span>
                </div>
                <div style="background: #333; border-radius: 4px; height: 8px;">
                    <div style="background: {color}; width: {score}%; height: 8px; border-radius: 4px;"></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_finding_card(finding: dict[str, Any]) -> None:
    """Render a single security finding as a card."""
    status = finding.get("status", "info")
    risk = finding.get("risk", "info")

    status_colors = {"pass": "#22c55e", "warn": "#eab308", "fail": "#ef4444", "info": "#3b82f6"}
    risk_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e",
        "info": "#3b82f6",
    }

    status_color = status_colors.get(status, "#3b82f6")
    risk_color = risk_colors.get(risk, "#3b82f6")

    st.markdown(
        f"""
        <div style="border: 1px solid #333; border-radius: 8px; padding: 12px;
                    margin-bottom: 8px; border-left: 4px solid {risk_color};">
            <div style="display: flex; gap: 8px; margin-bottom: 4px;">
                <span style="background: {status_color}22; color: {status_color};
                             padding: 2px 8px; border-radius: 4px; font-size: 12px;">{status.upper()}</span>
                <span style="background: {risk_color}22; color: {risk_color};
                             padding: 2px 8px; border-radius: 4px; font-size: 12px;">{risk.upper()}</span>
                <span style="color: #888; font-size: 12px;">{finding.get("category", "")}</span>
            </div>
            <div style="font-weight: 500; margin-bottom: 4px;">{finding.get("message", "")}</div>
            <div style="color: #888; font-size: 13px;">{finding.get("recommendation", "")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_entity_card(entity_type: str, value: str, confidence: float = 0.0, tags: list[str] | None = None) -> None:
    """Render an entity as a compact card."""
    type_colors = {
        "domain": "#3b82f6",
        "ip": "#8b5cf6",
        "email": "#22c55e",
        "username": "#eab308",
        "phone": "#f97316",
        "hash": "#ef4444",
        "btc": "#f59e0b",
        "url": "#06b6d4",
        "subdomain": "#6366f1",
        "cert": "#14b8a6",
        "asn": "#a855f7",
        "org": "#ec4899",
    }
    color = type_colors.get(entity_type, "#6b7280")
    tags_html = ""
    if tags:
        tags_html = " ".join(
            f'<span style="background: #333; padding: 1px 6px; border-radius: 3px; font-size: 11px;">{t}</span>'
            for t in tags[:5]
        )

    st.markdown(
        f"""
        <div style="border: 1px solid #333; border-radius: 6px; padding: 8px 12px;
                    margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
            <span style="background: {color}; color: white; padding: 2px 8px; border-radius: 4px;
                         font-size: 12px; font-weight: 500;">{entity_type.upper()}</span>
            <span style="font-family: monospace; font-size: 14px;">{value}</span>
            <span style="color: #888; font-size: 12px; margin-left: auto;">{confidence:.0f}%</span>
            {tags_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_timeline_event(event: dict[str, Any]) -> None:
    """Render a timeline event."""
    st.markdown(
        f"""
        <div style="border-left: 3px solid #3b82f6; padding: 8px 12px; margin-bottom: 8px; margin-left: 4px;">
            <div style="font-size: 12px; color: #888;">{event.get("timestamp", "")}</div>
            <div style="font-weight: 500;">{event.get("event", event.get("event_type", ""))}</div>
            <div style="color: #aaa; font-size: 13px;">{event.get("target", "")} —
                {event.get("details", event.get("description", ""))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
