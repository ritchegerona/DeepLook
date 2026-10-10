"""DeepLook CLI — Typer application with all commands."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from deeplook import __version__
from deeplook.core.ai_engine import AIEngine
from deeplook.core.attack_mapping import AttackReport, annotate_entities, map_workspace
from deeplook.core.cache import ResultCache
from deeplook.core.entity import ENTITY_COLORS, EntityType, create_entity
from deeplook.core.graph import IntelGraph
from deeplook.core.ingest import IngestResult, ingest_file
from deeplook.core.pivot import PivotEngine, PivotResult
from deeplook.core.plugin_loader import get_plugins_for_entity, load_all_plugins
from deeplook.core.watchlist import WatchCheckResult, WatchlistEngine
from deeplook.core.workspace import Workspace
from deeplook.output.correlation import correlate
from deeplook.output.csv_export import export_csv
from deeplook.output.excel_export import export_xlsx
from deeplook.output.json_export import export_json
from deeplook.output.security_report import render_security_json, render_security_report
from deeplook.output.stix_export import export_stix
from deeplook.output.table import render_edge_table, render_entity_table

app = typer.Typer(
    name="deeplook",
    help="Advanced Terminal OSINT & Threat Intelligence Framework",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

VERSION = f"DeepLook v{__version__}"


def get_workspace(name: str | None = None) -> Workspace:
    ws_name = name or "default"
    return Workspace(ws_name)


def run_plugins(
    target: str,
    workspace: Workspace,
    plugin_names: list[str] | None = None,
    cache: ResultCache | None = None,
) -> IntelGraph:
    entity = create_entity(target)
    workspace.add_entity(entity)

    all_plugins = load_all_plugins()
    plugins_to_run = []

    if plugin_names:
        for pname in plugin_names:
            if pname in all_plugins:
                plugins_to_run.append(all_plugins[pname])
    else:
        plugins_to_run = get_plugins_for_entity(entity.type.value, all_plugins)

    graph = workspace.to_graph()
    graph.add_entity(entity)

    for plugin in plugins_to_run:
        if not plugin.check_key():
            continue
        result = plugin.execute(entity, workspace, cache)
        for e in result.entities:
            workspace.add_entity(e)
            graph.add_entity(e)
        for edge in result.edges:
            workspace.add_edge(edge)
            graph.add_edge(edge)
        workspace.add_timeline_event(
            f"Plugin {plugin.name} completed",
            target=target,
            details={"entities": len(result.entities), "edges": len(result.edges)},
        )

    return workspace.to_graph()


# --- Main Commands ---


@app.command()
def version() -> None:
    """Show DeepLook version."""
    console.print(f"[bold cyan]{VERSION}[/bold cyan]")


@app.command()
def analyze(
    target: str = typer.Argument(help="Target to investigate (auto-detect type)"),
    workspace: str = typer.Option(None, "-w", "--workspace", help="Workspace name"),
    output_format: str = typer.Option("table", "-f", "--format", help="Output format: table, json"),
    export: str = typer.Option(None, "--export", help="Export format: csv, xlsx, json, stix"),
    export_path: str = typer.Option(None, "--output", help="Export file path"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip cache"),
) -> None:
    """Auto-detect entity type and run all relevant plugins."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Analyzing:[/bold] {target}", title="DeepLook", border_style="cyan"))

    graph = run_plugins(target, ws, cache=cache)

    entity = graph.find_entity(target)
    if entity:
        table = render_entity_table([entity], title=f"Target: {target}")
        console.print(table)

        neighbors = graph.get_neighbors(entity.id)
        if neighbors:
            edge_table = Table(title="Relationships", show_header=True)
            edge_table.add_column("Target", style="cyan")
            edge_table.add_column("Relationship", style="yellow")
            edge_table.add_column("Confidence", style="green")
            for neighbor, edge in neighbors:
                edge_table.add_row(neighbor.value, edge.label, f"{edge.confidence:.0f}%")
            console.print(edge_table)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def domain(
    target: str = typer.Argument(help="Domain to investigate"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    output_format: str = typer.Option("table", "-f", "--format"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate a domain (WHOIS, DNS, subdomains, web)."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Domain investigation:[/bold] {target}", border_style="green"))

    domain_plugins = [
        n
        for n in [
            "domain-whois",
            "domain-dns",
            "domain-subdomain",
            "domain-web",
            "web-tech",
            "web-headers",
            "web-cert",
            "web-links",
            "web-emails",
            "web-sitemap",
            "web-robots",
            "web-redirects",
            "web-meta",
            "web-dns-extra",
            "crtsh",
        ]
    ]
    graph = run_plugins(target, ws, plugin_names=domain_plugins, cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def ip(
    target: str = typer.Argument(help="IP address to investigate"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    output_format: str = typer.Option("table", "-f", "--format"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate an IP address (geolocation, reverse DNS, ports, WHOIS)."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]IP investigation:[/bold] {target}", border_style="blue"))

    ip_plugins = ["ip-geoloc", "ip-revdns", "ip-ports", "ip-whois"]
    graph = run_plugins(target, ws, plugin_names=ip_plugins, cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def email(
    target: str = typer.Argument(help="Email address to investigate"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    output_format: str = typer.Option("table", "-f", "--format"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate an email (syntax, MX records, breach check)."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Email investigation:[/bold] {target}", border_style="yellow"))

    email_plugins = ["email-syntax", "email-mx", "email-breach"]
    graph = run_plugins(target, ws, plugin_names=email_plugins, cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def username(
    target: str = typer.Argument(help="Username to investigate"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    output_format: str = typer.Option("table", "-f", "--format"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate a username across social platforms."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Username investigation:[/bold] {target}", border_style="magenta"))

    graph = run_plugins(target, ws, plugin_names=["username-social"], cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def phone(
    target: str = typer.Argument(help="Phone number to investigate"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate a phone number."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Phone investigation:[/bold] {target}", border_style="yellow"))

    graph = run_plugins(target, ws, plugin_names=["phone-lookup"], cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def hash(
    target: str = typer.Argument(help="File hash to investigate"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate a file hash (MD5/SHA1/SHA256)."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Hash investigation:[/bold] {target}", border_style="red"))

    graph = run_plugins(target, ws, plugin_names=["hash-lookup"], cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def btc(
    target: str = typer.Argument(help="Bitcoin wallet address"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Investigate a Bitcoin wallet address."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]BTC investigation:[/bold] {target}", border_style="cyan"))

    graph = run_plugins(target, ws, plugin_names=["btc-balance"], cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def website(
    target: str = typer.Argument(help="Website domain to profile"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    export: str = typer.Option(None, "--export"),
    export_path: str = typer.Option(None, "--output"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Deep website profiling (tech stack, headers, certs, links, emails)."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(Panel(f"[bold]Website profiling:[/bold] {target}", border_style="bright_green"))

    web_plugins = [
        "web-tech",
        "web-headers",
        "web-cert",
        "web-links",
        "web-emails",
        "web-sitemap",
        "web-robots",
        "web-redirects",
        "web-meta",
        "web-dns-extra",
    ]
    graph = run_plugins(target, ws, plugin_names=web_plugins, cache=cache)
    _print_graph_summary(graph, target)

    if export:
        _do_export(ws, export, export_path or f"deeplook-{target}.{export}")


@app.command()
def scan(
    file: str = typer.Option(..., "-f", "--file", help="File with targets (one per line)"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    concurrency: int = typer.Option(10, "-c", "--concurrency", help="Parallel scans"),
    export: str = typer.Option(None, "--export", help="Export format"),
    export_dir: str = typer.Option(None, "--export-dir", help="Export directory"),
    plugins: str = typer.Option(None, "--plugins", help="Comma-separated plugin names"),
) -> None:
    """Bulk scan targets from a file."""
    ws = get_workspace(workspace)
    cache = ResultCache()

    targets_file = Path(file)
    if not targets_file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    targets = [line.strip() for line in targets_file.read_text().splitlines() if line.strip()]
    plugin_names = plugins.split(",") if plugins else None

    console.print(Panel(f"[bold]Bulk scan:[/bold] {len(targets)} targets", border_style="cyan"))

    scan_id = ws.log_scan(f"scan -f {file}", targets, len(plugin_names or []))

    for i, target in enumerate(targets, 1):
        console.print(f"[dim]({i}/{len(targets)}[/dim] Scanning [cyan]{target}[/cyan]...")
        try:
            run_plugins(target, ws, plugin_names=plugin_names, cache=cache)
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")

    ws.finish_scan(scan_id, ws.to_graph().entity_count)
    console.print(f"\n[green]Scan complete. {ws.to_graph().entity_count} entities found.[/green]")

    if export:
        out_dir = Path(export_dir or ".")
        out_dir.mkdir(parents=True, exist_ok=True)
        _do_export(ws, export, str(out_dir / f"scan-{date.today()}.{export}"))


@app.command()
def graph(
    center: str = typer.Option(None, "-c", "--center", help="Center entity for ego graph"),
    depth: int = typer.Option(3, "-d", "--depth", help="Max graph depth"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    geo: bool = typer.Option(False, "--geo", help="Show geolocation map"),
) -> None:
    """Display ASCII entity relationship graph."""
    ws = get_workspace(workspace)
    g = ws.to_graph()

    if g.entity_count == 0:
        console.print("[dim]No entities in workspace. Run an investigation first.[/dim]")
        return

    if geo:
        locations = {}
        for entity in g.entities_by_type(EntityType.IP):
            if "lat" in entity.metadata and "lon" in entity.metadata:
                locations[entity.value] = (entity.metadata["lat"], entity.metadata["lon"])
        text = g.render_map(locations)
    else:
        text = g.render_ascii(center=center, max_depth=depth)
    console.print(text)


@app.command()
def correlate_cmd(
    workspace: str = typer.Option(None, "-w", "--workspace"),
) -> None:
    """Run cross-target correlation analysis."""
    ws = get_workspace(workspace)
    result = correlate(ws)

    console.print(Panel("[bold]Correlation Report[/bold]", border_style="cyan"))

    for corr_type, findings in result.items():
        if findings:
            table = Table(title=corr_type.replace("_", " ").title(), show_header=True)
            table.add_column("Description", style="cyan")
            table.add_column("Entities", style="yellow")
            for finding in findings:
                desc = finding.get("description", "")
                entities = ", ".join(finding.get("entities", []))
                table.add_row(desc, entities)
            console.print(table)


@app.command("export")
def export_cmd(
    format: str = typer.Option("json", "-f", "--format", help="Export format: csv, xlsx, json, stix"),
    report: str = typer.Option("full", "--report", help="Report template"),
    output: str = typer.Option(None, "-o", "--output", help="Output file path"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
) -> None:
    """Export workspace data."""
    ws = get_workspace(workspace)
    out_path = output or f"deeplook-export.{format}"
    _do_export(ws, format, out_path, report)


@app.command("workspace")
def workspace_cmd(
    action: str = typer.Argument(help="Action: new, list, open"),
    name: str = typer.Option(None, help="Workspace name"),
) -> None:
    """Manage investigation workspaces."""
    if action == "list":
        workspaces = Workspace.list_workspaces()
        if not workspaces:
            console.print("[dim]No workspaces found.[/dim]")
            return
        table = Table(title="Workspaces", show_header=True)
        table.add_column("Name", style="cyan")
        for ws_name in workspaces:
            table.add_row(ws_name)
        console.print(table)

    elif action == "new":
        if not name:
            console.print("[red]Specify --name for new workspace[/red]")
            raise typer.Exit(1)
        ws = Workspace.create(name)
        console.print(f"[green]Workspace '{name}' created at {ws.db_path}[/green]")

    elif action == "open":
        if not name:
            console.print("[red]Specify --name to open workspace[/red]")
            raise typer.Exit(1)
        ws = get_workspace(name)
        g = ws.to_graph()
        console.print(f"[green]Workspace '{name}': {g.entity_count} entities, {g.edge_count} edges[/green]")


@app.command("plugins")
def plugins_cmd(
    action: str = typer.Option("list", "-a", "--action", help="Action: list, info"),
    name: str = typer.Option(None, "-n", "--name", help="Plugin name for info"),
) -> None:
    """List or get info about plugins."""
    all_plugins = load_all_plugins()

    if action == "list":
        table = Table(title="Loaded Plugins", show_header=True)
        table.add_column("Name", style="cyan")
        table.add_column("Entity Types", style="yellow")
        table.add_column("Key Required", style="red")
        table.add_column("Confidence", style="green")
        for pname, plugin in sorted(all_plugins.items()):
            info = plugin.info()
            table.add_row(
                info["name"],
                ", ".join(info["entity_types"]),
                "Yes" if info["requires_key"] else "No",
                f"{info['confidence']:.0%}",
            )
        console.print(table)

    elif action == "info" and name:
        plugin = all_plugins.get(name)
        if plugin is not None:
            info = plugin.info()
            console.print(Panel(json.dumps(info, indent=2), title=f"Plugin: {name}"))
        else:
            console.print(f"[red]Plugin not found: {name}[/red]")


@app.command()
def query(
    question: str = typer.Argument(help="Natural language question about your data"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
) -> None:
    """Natural language query against workspace data."""
    ws = get_workspace(workspace)
    results = ws.search(question)

    console.print(Panel(f"[bold]Query:[/bold] {question}", border_style="cyan"))

    if results["entities"]:
        console.print(f"\n[bold]Entities ({len(results['entities'])}):[/bold]")
        table = render_entity_table(results["entities"])
        console.print(table)

    if results["edges"]:
        console.print(f"\n[bold]Relationships ({len(results['edges'])}):[/bold]")
        edge_table = render_edge_table(results["edges"], {e.id: e for e in results["entities"]})
        console.print(edge_table)

    if results["notes"]:
        console.print(f"\n[bold]Notes ({len(results['notes'])}):[/bold]")
        for note in results["notes"]:
            console.print(f"  [dim]{note['created_at']}[/dim] {note['content']}")


@app.command()
def diff(
    scan1: str = typer.Argument(help="Path to first scan JSON"),
    scan2: str = typer.Argument(help="Path to second scan JSON"),
) -> None:
    """Compare two investigation snapshots."""
    path1, path2 = Path(scan1), Path(scan2)
    if not path1.exists() or not path2.exists():
        console.print("[red]Both files must exist[/red]")
        raise typer.Exit(1)

    data1 = json.loads(path1.read_text())
    data2 = json.loads(path2.read_text())

    entities1 = {e["value"] for e in data1.get("entities", [])}
    entities2 = {e["value"] for e in data2.get("entities", [])}

    added = entities2 - entities1
    removed = entities1 - entities2
    common = entities1 & entities2

    console.print(Panel("[bold]Investigation Diff[/bold]", border_style="cyan"))
    console.print(f"  [green]+ Added:[/green] {len(added)}")
    console.print(f"  [red]- Removed:[/red] {len(removed)}")
    console.print(f"  [dim]= Common:[/dim] {len(common)}")

    if added:
        console.print("\n[bold green]New entities:[/bold green]")
        for v in sorted(added):
            console.print(f"  + {v}")
    if removed:
        console.print("\n[bold red]Removed entities:[/bold red]")
        for v in sorted(removed):
            console.print(f"  - {v}")


@app.command()
def note(
    content: str = typer.Argument(help="Note content"),
    entity: str = typer.Option(None, "-e", "--entity", help="Attach to entity"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
) -> None:
    """Add an investigation note."""
    ws = get_workspace(workspace)
    entity_id = None
    if entity:
        found = ws.find_entity_by_value(entity)
        if found:
            entity_id = found.id
    ws.add_note(entity_id, content)
    ws.add_timeline_event(f"Note added: {content[:50]}...")
    console.print("[green]Note added.[/green]")


@app.command()
def timeline(
    workspace: str = typer.Option(None, "-w", "--workspace"),
) -> None:
    """Show investigation timeline."""
    ws = get_workspace(workspace)
    events = ws.get_timeline()

    if not events:
        console.print("[dim]No timeline events.[/dim]")
        return

    table = Table(title="Investigation Timeline", show_header=True)
    table.add_column("Timestamp", style="dim")
    table.add_column("Event", style="cyan")
    table.add_column("Target", style="yellow")

    for event in events:
        table.add_row(event["timestamp"], event["event"], event.get("target", ""))
    console.print(table)


@app.command("search")
def search_cmd(
    query: str = typer.Argument(help="Search query"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
) -> None:
    """Search workspace for entities, edges, and notes."""
    ws = get_workspace(workspace)
    results = ws.search(query)

    console.print(f"[bold]Search results for:[/bold] {query}\n")

    if results["entities"]:
        table = render_entity_table(results["entities"], title="Entities")
        console.print(table)
    if results["edges"]:
        edge_table = render_edge_table(results["edges"], {e.id: e for e in results["entities"]})
        console.print(edge_table)
    if results["notes"]:
        for note in results["notes"]:
            console.print(f"  [dim]{note['created_at']}[/dim] {note['content']}")


@app.command()
def security(
    target: str = typer.Argument(help="Target to assess (domain or IP)"),
    workspace: str = typer.Option(None, "-w", "--workspace"),
    security_type: str = typer.Option(
        None, "-t", "--type", help="Security check type: breach, vuln, misconfig, exposure"
    ),
    export: str = typer.Option(None, "--export", help="Export format: json, xlsx, stix"),
    export_path: str = typer.Option(None, "--output", help="Export file path"),
    output_format: str = typer.Option("table", "-f", "--format", help="Output format: table, json"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip cache"),
) -> None:
    """Security vulnerability and breach assessment."""
    from deeplook.core.security_scorer import Finding, FindingStatus, RiskLevel, SecurityScorer

    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()

    console.print(
        Panel(
            f"[bold]Security assessment:[/bold] {target}",
            title="DeepLook Security",
            border_style="red",
        )
    )

    security_plugins = {
        "breach": ["breach-domain", "breach-ip", "malware-hash"],
        "vuln": ["cve-check", "subdomain-takeover", "ssl-vuln"],
        "misconfig": ["dns-security", "header-security", "email-security"],
        "exposure": ["exposed-services", "sensitive-files", "api-exposure"],
    }

    if security_type:
        plugin_names = security_plugins.get(security_type, [])
    else:
        plugin_names = []
        for plugins in security_plugins.values():
            plugin_names.extend(plugins)

    entity = create_entity(target)
    ws.add_entity(entity)
    all_plugins = load_all_plugins()

    scorer = SecurityScorer()

    for pname in plugin_names:
        if pname not in all_plugins:
            continue
        plugin = all_plugins[pname]
        if not plugin.check_key():
            continue

        console.print(f"  [dim]Running {pname}...[/dim]")
        result = plugin.execute(entity, ws, cache)

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

        ws.add_timeline_event(
            f"Security plugin {pname} completed",
            target=target,
            details={"findings": len(findings)},
        )

    report = scorer.calculate(target)

    if output_format == "json":
        import json as json_mod

        report_data = render_security_json(report)
        console.print(json_mod.dumps(report_data, indent=2))
    else:
        render_security_report(report)

    if export:
        if export == "json":
            report_data = render_security_json(report)
            out = Path(export_path or f"security-{target}.json")
            out.write_text(json.dumps(report_data, indent=2))
            console.print(f"[green]Exported security report to {out}[/green]")
        else:
            _do_export(ws, export, export_path or f"security-{target}.{export}")


@app.command()
def pivot(
    target: str = typer.Argument(help="Seed indicator to pivot from (auto-detect type)"),
    workspace: str = typer.Option(None, "-w", "--workspace", help="Workspace name"),
    depth: int = typer.Option(2, "--depth", "-d", help="Maximum pivot depth"),
    max_entities: int = typer.Option(50, "--max-entities", help="Maximum unique entities to discover"),
    plugins: str = typer.Option(None, "--plugins", help="Comma-separated plugin names to restrict to"),
    export: str = typer.Option(None, "--export", help="Export format: csv, xlsx, json, stix"),
    export_path: str = typer.Option(None, "--output", help="Export file path"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip cache"),
) -> None:
    """Recursively expand a seed indicator (e.g. IP -> ASN/org -> domains)."""
    ws = get_workspace(workspace)
    cache = None if no_cache else ResultCache()
    plugin_filter = [p.strip() for p in plugins.split(",") if p.strip()] if plugins else None

    console.print(
        Panel(
            f"[bold]Pivoting:[/bold] {target}  (depth={depth}, max-entities={max_entities})",
            title="DeepLook",
            border_style="magenta",
        )
    )

    try:
        engine = PivotEngine(
            ws,
            max_depth=depth,
            max_entities=max_entities,
            cache=cache,
            plugin_filter=plugin_filter,
        )
        result = engine.pivot(target)
    except ValueError as exc:
        console.print(f"[red]Cannot pivot '{target}': {exc}[/red]")
        raise typer.Exit(code=1) from exc

    _print_pivot_summary(result)

    if export:
        _do_export(ws, export, export_path or f"deeplook-pivot-{target}.{export}")


@app.command()
def attack(
    target: str = typer.Argument(None, help="Target to scope to (optional; default: whole workspace)"),
    workspace: str = typer.Option(None, "-w", "--workspace", help="Workspace name"),
    annotate: bool = typer.Option(False, "--annotate", help="Persist technique IDs into entity metadata"),
    output_format: str = typer.Option("table", "-f", "--format", help="Output format: table, json"),
) -> None:
    """Map findings to MITRE ATT&CK (Reconnaissance / Resource Development)."""
    ws = get_workspace(workspace)

    entities = None
    scope = ws.name
    if target:
        graph = ws.to_graph()
        center = graph.find_entity(target)
        if center is None:
            console.print(f"[yellow]'{target}' not found in workspace; mapping entire workspace.[/yellow]")
        else:
            entities = [center]
            seen = {center.id}
            for neighbor, _ in graph.get_neighbors(center.id):
                if neighbor.id not in seen:
                    seen.add(neighbor.id)
                    entities.append(neighbor)
            scope = target

    report = annotate_entities(ws, entities) if annotate else map_workspace(ws, entities)

    if output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_attack_report(report, scope)

    if annotate:
        console.print(
            f"[green]Annotated {report.entity_count - len(report.unmapped)} entities with ATT&CK IDs.[/green]"
        )


@app.command()
def ingest(
    file: str = typer.Option(..., "-f", "--file", help="Feed file to ingest"),
    workspace: str = typer.Option(None, "-w", "--workspace", help="Workspace name"),
    file_format: str = typer.Option("auto", "--format", help="Format: auto, text, csv, stix, misp"),
    tags: str = typer.Option(None, "--tags", help="Comma-separated tags to apply to ingested indicators"),
    output_format: str = typer.Option("table", "--output-format", help="Output format: table, json"),
) -> None:
    """Ingest IOC feeds (plain/defanged text, CSV, STIX 2.1, MISP) into a workspace."""
    path = Path(file)
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(code=1)

    ws = get_workspace(workspace)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

    result = ingest_file(ws, path, fmt=file_format, tags=tag_list)

    if output_format == "json":
        console.print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_ingest_summary(result)


@app.command("watch")
def watch_cmd(
    action: str = typer.Argument(help="Action: add, list, remove, check"),
    value: str = typer.Argument(None, help="Indicator (add) or watch id (remove/check)"),
    workspace: str = typer.Option(None, "-w", "--workspace", help="Workspace name"),
    tags: str = typer.Option(None, "--tags", help="Comma-separated tags (add)"),
    note: str = typer.Option("", "--note", help="Note (add)"),
    output_format: str = typer.Option("table", "--output-format", help="Output format: table, json"),
    report: str = typer.Option(None, "--report", help="Append a JSON-lines run log to this file (check)"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change", help="Exit 2 if any changes are detected (check)"),
) -> None:
    """Manage the watchlist and check watched indicators for changes."""
    ws = get_workspace(workspace)

    if action == "add":
        if not value:
            console.print("[red]Provide an indicator value to watch.[/red]")
            raise typer.Exit(1)
        try:
            entity = create_entity(value)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
        watch_id = ws.add_watch(entity.type.value, entity.value, tags=tag_list, note=note)
        console.print(f"[green]Watching {entity.type.value} '{entity.value}' (id {watch_id}).[/green]")

    elif action == "list":
        items = ws.list_watch()
        if output_format == "json":
            console.print(json.dumps(items, indent=2))
        elif not items:
            console.print("[dim]Watchlist is empty.[/dim]")
        else:
            _print_watchlist(items)

    elif action == "remove":
        if not value or not value.isdigit():
            console.print("[red]Provide the watch id to remove.[/red]")
            raise typer.Exit(1)
        if ws.remove_watch(int(value)):
            console.print(f"[green]Removed watch {value}.[/green]")
        else:
            console.print(f"[red]No watch with id {value}.[/red]")

    elif action == "check":
        if not ws.list_watch():
            console.print("[dim]Watchlist is empty.[/dim]")
            return
        engine = WatchlistEngine(ws)
        if value and value.isdigit():
            watch = ws.get_watch(int(value))
            if not watch:
                console.print(f"[red]No watch with id {value}.[/red]")
                raise typer.Exit(1)
            results = [engine.check(watch)]
        else:
            results = engine.check_all()
        if output_format == "json":
            console.print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            _print_watch_results(results)

        if report:
            report_path = Path(report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "checked_at": results[0].checked_at if results else datetime.now(UTC).isoformat(),
                "workspace": ws.name,
                "changes": sum(len(r.changes) for r in results),
                "results": [r.to_dict() for r in results],
            }
            with report_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
            console.print(f"[dim]Logged run to {report_path}[/dim]")

        if fail_on_change and any(r.has_changes for r in results):
            raise typer.Exit(2)

    else:
        console.print(f"[red]Unknown action: {action} (use add, list, remove, check).[/red]")
        raise typer.Exit(1)


# --- Helpers ---


def _print_attack_report(report: AttackReport, scope: str) -> None:
    table = Table(title=f"ATT&CK Coverage — {scope}", show_lines=True, expand=True)
    table.add_column("Technique", style="bold cyan")
    table.add_column("Name")
    table.add_column("Tactic", style="magenta")
    table.add_column("Entities", justify="right")

    for usage in report.techniques:
        table.add_row(
            usage.technique.id,
            usage.technique.name,
            usage.technique.tactic,
            str(len(usage.entities)),
        )
    console.print(table)

    console.print(
        f"[bold]{len(report.techniques)} techniques[/bold] across "
        f"[bold]{report.entity_count}[/bold] entities "
        f"({', '.join(report.tactics) if report.tactics else 'none'})"
    )
    if report.unmapped:
        console.print(f"[dim]{len(report.unmapped)} entities had no ATT&CK mapping.[/dim]")


def _print_ingest_summary(result: IngestResult) -> None:
    console.print(Panel(f"[bold]Ingested:[/bold] {result.source} ({result.format})", border_style="cyan"))

    if result.samples:
        table = Table(title="Indicators", expand=True)
        table.add_column("Type", style="bold")
        table.add_column("Value")
        for sample in result.samples:
            try:
                entity_type: EntityType | None = EntityType(sample["type"])
            except ValueError:
                entity_type = None
            color = ENTITY_COLORS.get(entity_type, "white") if entity_type else "white"
            table.add_row(Text(sample["type"], style=color), sample["value"])
        console.print(table)

    console.print(
        f"[bold]Added:[/bold] {result.added}  "
        f"[bold]Skipped:[/bold] {result.skipped}  "
        f"[bold]Total:[/bold] {result.total}"
    )
    for error in result.errors[:10]:
        console.print(f"[yellow]warning:[/yellow] {error}")
    if len(result.errors) > 10:
        console.print(f"[dim]... and {len(result.errors) - 10} more warnings[/dim]")


def _print_watchlist(items: list[dict]) -> None:
    table = Table(title="Watchlist", show_lines=True, expand=True)
    table.add_column("ID", justify="right", style="bold")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Tags")
    table.add_column("Last Checked")

    for item in items:
        try:
            entity_type: EntityType | None = EntityType(item["type"])
        except ValueError:
            entity_type = None
        color = ENTITY_COLORS.get(entity_type, "white") if entity_type else "white"
        table.add_row(
            str(item["id"]),
            Text(item["type"], style=color),
            item["value"],
            ", ".join(item["tags"]) or "-",
            item["last_checked"] or "never",
        )
    console.print(table)


def _print_watch_results(results: list[WatchCheckResult]) -> None:
    total = sum(len(r.changes) for r in results)
    console.print(Panel(f"[bold]Watchlist check:[/bold] {len(results)} items, {total} changes", border_style="cyan"))

    for result in results:
        if result.error:
            console.print(f"[yellow]{result.item.value}:[/yellow] {result.error}")
        for change in result.changes:
            color = "green" if change.change == "added" else "red"
            sign = "+" if change.change == "added" else "-"
            console.print(f"  [{color}]{sign}[/{color}] {change.detail}")

    if not total:
        console.print("[dim]No changes detected.[/dim]")


def _print_pivot_summary(result: PivotResult) -> None:
    table = Table(title=f"Pivot from {result.root}", show_lines=True, expand=True)
    table.add_column("Depth", justify="right", style="bold")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Discovered By")

    for node in sorted(result.nodes, key=lambda n: (n.depth, n.type, n.value)):
        try:
            entity_type: EntityType | None = EntityType(node.type)
        except ValueError:
            entity_type = None
        color = ENTITY_COLORS.get(entity_type, "white") if entity_type else "white"
        table.add_row(
            str(node.depth),
            Text(node.type, style=color),
            node.value,
            node.plugin or "-",
        )
    console.print(table)

    console.print(
        f"[bold]Entities added:[/bold] {result.entities_added}  "
        f"[bold]Edges added:[/bold] {result.edges_added}  "
        f"[bold]Plugins run:[/bold] {result.plugins_run}"
    )
    if result.truncated:
        console.print("[yellow]Entity budget reached; pivot truncated. Increase --max-entities for more.[/yellow]")
    if result.errors:
        for warning in result.errors:
            console.print(f"[yellow]warning:[/yellow] {warning}")


def _print_graph_summary(graph: IntelGraph, target: str) -> None:
    entity = graph.find_entity(target)
    if entity:
        table = render_entity_table([entity], title=f"Target: {target}")
        console.print(table)

    neighbors = graph.get_neighbors(entity.id) if entity else []
    if neighbors:
        edge_table = Table(title="Relationships", show_header=True)
        edge_table.add_column("Target", style="cyan")
        edge_table.add_column("Relationship", style="yellow")
        edge_table.add_column("Confidence", style="green")
        for neighbor, edge in neighbors[:20]:
            edge_table.add_row(neighbor.value, edge.label, f"{edge.confidence:.0f}%")
        if len(neighbors) > 20:
            edge_table.add_row(f"... and {len(neighbors) - 20} more", "", "")
        console.print(edge_table)

    msg = f"\n[green]{graph.entity_count} entities, "
    msg += f"{graph.edge_count} relationships discovered[/green]"
    console.print(msg)


def _do_export(ws: Workspace, fmt: str, path: str, report: str = "full") -> None:
    out = Path(path)
    if fmt == "csv":
        result = export_csv(ws, out)
        console.print(f"[green]Exported CSV to {str(result)}[/green]")
    elif fmt == "xlsx":
        result = export_xlsx(ws, out, report)
        console.print(f"[green]Exported Excel to {str(result)}[/green]")
    elif fmt == "json":
        result = export_json(ws, out)
        console.print(f"[green]Exported JSON to {str(result)}[/green]")
    elif fmt == "stix":
        result = export_stix(ws, out)
        console.print(f"[green]Exported STIX to {str(result)}[/green]")
    else:
        console.print(f"[red]Unknown format: {fmt}[/red]")


@app.command("ai")
def ai_cmd(
    action: str = typer.Argument(help="Action: summarize, pivot, report, query"),
    question: str = typer.Option(None, "-q", "--question", help="Question (for the query action)"),
    workspace: str = typer.Option(None, "-w", "--workspace", help="Workspace name"),
    output: str = typer.Option(None, "-o", "--output", help="Write the result to a file"),
) -> None:
    """AI-powered analysis (requires OPENAI_API_KEY or ANTHROPIC_API_KEY)."""
    engine = AIEngine()
    ws = get_workspace(workspace)

    if action == "summarize":
        result = engine.summarize(ws)
    elif action == "pivot":
        result = engine.suggest_pivots(ws)
    elif action == "report":
        result = engine.generate_report(ws)
    elif action == "query":
        if not question:
            console.print("[red]Provide a question with -q/--question.[/red]")
            raise typer.Exit(code=1)
        result = engine.natural_query(ws, question)
    else:
        console.print(f"[red]Unknown action: {action} (use summarize, pivot, report, query).[/red]")
        raise typer.Exit(code=1)

    if output:
        Path(output).write_text(result)
        console.print(f"[green]Written to {output}[/green]")
    else:
        console.print(result)


@app.command()
def gui() -> None:
    """Launch the DeepLook GUI dashboard in your browser."""
    import subprocess
    import sys

    from deeplook import __version__

    console.print(
        Panel(
            f"[bold]DeepLook GUI v{__version__}[/bold]\n\n"
            "Launching Streamlit dashboard...\n"
            "The GUI will open in your default browser.\n"
            "Press Ctrl+C to stop the server.",
            title="🔍 DeepLook",
            border_style="blue",
        )
    )

    gui_path = Path(__file__).parent / "gui" / "app.py"
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(gui_path)])


if __name__ == "__main__":
    app()
