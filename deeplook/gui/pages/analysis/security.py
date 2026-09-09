"""Security assessment page."""

from __future__ import annotations

import streamlit as st

from deeplook.core.entity import create_entity
from deeplook.core.plugin_loader import load_all_plugins
from deeplook.core.security_scorer import Finding, FindingStatus, RiskLevel, SecurityScorer
from deeplook.gui.components.charts import render_category_scores, render_finding_card, render_security_score
from deeplook.gui.components.data import findings_to_df
from deeplook.gui.components.state import get_workspace

st.title("🛡️ Security Assessment")

target = st.text_input("Target", placeholder="example.com or 8.8.8.8", key="security_target")

col1, col2 = st.columns([1, 3])
with col1:
    run_btn = st.button("Assess", type="primary", key="security_run")
with col2:
    security_type = st.selectbox(
        "Security Check Type",
        ["All", "Breach", "Vuln", "Misconfig", "Exposure"],
        key="security_type",
    )

SECURITY_PLUGINS = {
    "Breach": ["breach-domain", "breach-ip", "malware-hash"],
    "Vuln": ["cve-check", "subdomain-takeover", "ssl-vuln"],
    "Misconfig": ["dns-security", "header-security", "email-security"],
    "Exposure": ["exposed-services", "sensitive-files", "api-exposure"],
}

if run_btn and target:
    ws = get_workspace()
    if not ws:
        st.error("No workspace selected. Go to Workspace page to create one.")
        st.stop()

    entity = create_entity(target)
    ws.add_entity(entity)
    all_plugins = load_all_plugins()

    if security_type == "All":
        plugin_names = []
        for plugins in SECURITY_PLUGINS.values():
            plugin_names.extend(plugins)
    else:
        plugin_names = SECURITY_PLUGINS.get(security_type, [])

    progress = st.progress(0, text="Starting security assessment...")
    status = st.status("Running security plugins...", expanded=True)

    scorer = SecurityScorer()

    for i, pname in enumerate(plugin_names):
        if pname not in all_plugins:
            continue
        plugin = all_plugins[pname]
        if not plugin.check_key():
            status.update(label=f"⏭️ Skipping {pname} (API key required)", state="running")
            continue

        status.update(label=f"Running {pname}...", state="running")
        progress.progress((i + 1) / len(plugin_names), text=f"Running {pname}...")

        result = plugin.execute(entity, ws)

        for e in result.entities:
            ws.add_entity(e)
        for edge in result.edges:
            ws.add_edge(edge)

        findings = result.metadata.get("findings", [])
        for f_data in findings:
            finding = Finding(
                category=f_data.get("category", "Unknown"),
                check=f_data.get("check", pname),
                status=FindingStatus(f_data.get("status", "info")),
                risk=RiskLevel(f_data.get("risk", "info")),
                message=f_data.get("message", ""),
                recommendation=f_data.get("recommendation", ""),
                details=f_data.get("details", {}),
            )
            scorer.add_finding(finding)

    report = scorer.calculate(target)

    status.update(label="Security assessment complete!", state="complete")
    progress.progress(1.0, text="Done!")

    ws.add_timeline_event("Security assessment completed", target=target)

    st.divider()

    # Score display
    col1, col2 = st.columns([1, 2])
    with col1:
        render_security_score(report.overall_score, report.risk_level.value)
    with col2:
        render_category_scores([{"name": c.name, "score": c.score, "weight": c.weight} for c in report.categories])

    st.divider()

    # Findings
    st.subheader(f"Findings ({len(report.all_findings)})")

    if report.all_findings:
        # Filter by risk level
        risk_filter = st.multiselect(
            "Filter by risk",
            ["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium"],
            key="security_risk_filter",
        )

        filtered = [f for f in report.all_findings if f.risk.value in risk_filter]

        for finding in filtered:
            render_finding_card(
                {
                    "category": finding.category,
                    "check": finding.check,
                    "status": finding.status.value,
                    "risk": finding.risk.value,
                    "message": finding.message,
                    "recommendation": finding.recommendation,
                }
            )

        with st.expander("Findings Table"):
            df = findings_to_df(
                [
                    {
                        "category": f.category,
                        "check": f.check,
                        "status": f.status.value,
                        "risk": f.risk.value,
                        "message": f.message,
                        "recommendation": f.recommendation,
                    }
                    for f in report.all_findings
                ]
            )
            st.dataframe(df, use_container_width=True, height=300)
    else:
        st.success("No security findings detected.")

elif run_btn:
    st.warning("Please enter a target for security assessment.")
