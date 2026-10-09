"""Security report formatter for terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from deeplook.core.security_scorer import (
    FindingStatus,
    RiskLevel,
    SecurityReport,
)

console = Console()

RISK_STYLES = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
    RiskLevel.INFO: "dim",
}

STATUS_STYLES = {
    FindingStatus.PASS: "green",
    FindingStatus.WARN: "yellow",
    FindingStatus.FAIL: "red",
    FindingStatus.INFO: "dim",
}

STATUS_ICONS = {
    FindingStatus.PASS: "PASS",
    FindingStatus.WARN: "WARN",
    FindingStatus.FAIL: "FAIL",
    FindingStatus.INFO: "INFO",
}


def render_security_report(report: SecurityReport) -> None:
    """Render a full security assessment report to terminal."""
    _render_header(report)
    _render_score_table(report)
    _render_findings(report)
    _render_recommendations(report)


def _render_header(report: SecurityReport) -> None:
    score_color = "green" if report.overall_score >= 80 else "yellow" if report.overall_score >= 60 else "red"
    header = Text()
    header.append(f"Target: {report.target}\n", style="bold cyan")
    header.append("Overall Score: ", style="bold")
    header.append(f"{report.overall_score}/100", style=f"bold {score_color}")
    header.append(f" ({report.risk_emoji})\n", style=RISK_STYLES.get(report.risk_level, "white"))
    console.print(Panel(header, title="Security Assessment", border_style="cyan"))


def _render_score_table(report: SecurityReport) -> None:
    table = Table(show_header=True, border_style="dim")
    table.add_column("Category", style="bold")
    table.add_column("Score", justify="center")
    table.add_column("Status", justify="center")

    for cat in report.categories:
        score_color = "green" if cat.score >= 80 else "yellow" if cat.score >= 60 else "red"
        status_color = "green" if cat.score >= 80 else "yellow" if cat.score >= 60 else "red"
        table.add_row(
            cat.name,
            Text(f"{cat.score}/100", style=score_color),
            Text(cat.status_emoji, style=status_color),
        )

    console.print(table)


def _render_findings(report: SecurityReport) -> None:
    console.print("\n[bold]FINDINGS[/bold]\n")

    sorted_findings = sorted(
        report.all_findings,
        key=lambda f: list(RiskLevel).index(f.risk),
    )

    for finding in sorted_findings:
        icon = STATUS_ICONS.get(finding.status, "?")
        style = STATUS_STYLES.get(finding.status, "white")

        line = Text()
        line.append(f"  [{icon}] ", style=style)
        line.append(f"{finding.message}\n")
        if finding.recommendation:
            line.append(f"       → {finding.recommendation}\n", style="dim")

        console.print(line)


def _render_recommendations(report: SecurityReport) -> None:
    critical = [f for f in report.all_findings if f.risk == RiskLevel.CRITICAL]
    high = [f for f in report.all_findings if f.risk == RiskLevel.HIGH]

    if not critical and not high:
        console.print("\n[green]No critical or high-risk issues found.[/green]\n")
        return

    console.print("\n[bold red]PRIORITY ACTIONS[/bold red]\n")

    for i, finding in enumerate(critical + high, 1):
        risk_label = "CRITICAL" if finding.risk == RiskLevel.CRITICAL else "HIGH"
        console.print(f"  {i}. [{risk_label}] {finding.message}")
        if finding.recommendation:
            console.print(f"     → {finding.recommendation}", style="dim")

    console.print()


def render_security_json(report: SecurityReport) -> dict:
    """Convert security report to JSON-serializable dict."""
    return {
        "target": report.target,
        "overall_score": report.overall_score,
        "risk_level": report.risk_level.value,
        "categories": [
            {
                "name": cat.name,
                "score": cat.score,
                "weight": cat.weight,
                "status": cat.status_emoji,
                "findings": [
                    {
                        "category": f.category,
                        "check": f.check,
                        "status": f.status.value,
                        "risk": f.risk.value,
                        "message": f.message,
                        "recommendation": f.recommendation,
                        "details": f.details,
                    }
                    for f in cat.findings
                ],
            }
            for cat in report.categories
        ],
        "summary": {
            "critical": len(report.critical_findings),
            "high": len(report.high_findings),
            "medium": len(report.medium_findings),
            "total_findings": len(report.all_findings),
        },
    }
