"""Command Line Interface (CLI) for the CCK platform using Typer and Rich."""

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cck import __version__
from cck.contracts.action import AgentAction
from cck.core.config import get_settings
from cck.core.types import VerdictDecision
from cck.runtime.engine import CCKControlPlane

app = typer.Typer(
    name="cck",
    help="CCK (Command & Control Kit) - Reliability and Governance Platform for AI Agent Actions",
    add_completion=False,
)
console = Console()


@app.command("version")
def version() -> None:
    """Print CCK version."""
    console.print(f"[bold cyan]CCK Platform[/bold cyan] version [green]{__version__}[/green]")


@app.command("info")
def info() -> None:
    """Display CCK runtime configuration and platform status."""
    settings = get_settings()

    table = Table(title="CCK Control Plane Status", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Version", __version__)
    table.add_row("Environment", settings.environment)
    table.add_row("SQLite Database Path", str(settings.sqlite_db_path))
    table.add_row("Database URL", settings.database_url)
    table.add_row("Default API Host", f"{settings.api_host}:{settings.api_port}")
    table.add_row("Tamper-Evident Chain", "Enabled" if settings.enable_tamper_evident_chain else "Disabled")
    table.add_row("Default Risk Threshold", str(settings.default_risk_threshold))

    console.print(table)


@app.command("init-db")
def init_db(
    db_path: Path = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Custom path to SQLite database",
    ),
) -> None:
    """Initialize CCK database schemas and seed baseline governance policies."""

    async def _init() -> None:
        settings = get_settings()
        target_path = db_path or settings.sqlite_db_path
        control_plane = CCKControlPlane(settings=settings)
        if db_path:
            from cck.storage.sqlite import SQLiteStorageBackend
            control_plane.storage = SQLiteStorageBackend(db_path=target_path)

        with console.status(f"[bold blue]Initializing database at {target_path}..."):
            await control_plane.initialize()
            policies = await control_plane.list_policies()
            await control_plane.shutdown()

        console.print(
            Panel.fit(
                f"[bold green]✓[/bold green] Database initialized successfully at: [cyan]{target_path}[/cyan]\n"
                f"[bold green]✓[/bold green] Active security policies loaded: [yellow]{len(policies)}[/yellow]",
                title="CCK Database Setup",
                border_style="green",
            )
        )

    asyncio.run(_init())


@app.command("inspect-action")
def inspect_action(
    scenario_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to JSON file containing AgentAction payload",
    ),
) -> None:
    """Evaluate an agent action scenario file against CCK safety guardrails."""

    async def _inspect() -> None:
        content = scenario_path.read_text(encoding="utf-8")
        action = AgentAction.model_validate_json(content)

        control_plane = CCKControlPlane()
        await control_plane.initialize()
        verdict = await control_plane.evaluate_action(action)
        await control_plane.shutdown()

        color = "green"
        if verdict.decision == VerdictDecision.BLOCK:
            color = "red"
        elif verdict.decision == VerdictDecision.REQUIRE_APPROVAL:
            color = "yellow"

        verdict_panel = (
            f"[bold {color}]Decision:[/bold {color}] {verdict.decision.value}\n"
            f"[bold]Risk Tier:[/bold] {verdict.risk_level.value} (Score: {verdict.risk_score:.2f})\n"
            f"[bold]Reason:[/bold] {verdict.reason}\n"
            f"[bold]Action ID:[/bold] {verdict.action_id}\n"
            f"[bold]Target Capability:[/bold] {action.capability} -> {action.target}\n"
        )

        if verdict.matched_policies:
            verdict_panel += "\n[bold underline]Matched Policies:[/bold underline]\n"
            for match in verdict.matched_policies:
                verdict_panel += (
                    f" • [{match.rule_id}] [bold]{match.rule_name}[/bold] -> {match.effect.value}\n"
                    f"   Detail: {match.reason}\n"
                )

        if verdict.remediation_suggestions:
            verdict_panel += "\n[bold underline]Remediation Suggestions:[/bold underline]\n"
            for sug in verdict.remediation_suggestions:
                verdict_panel += f" ➜ {sug}\n"

        console.print(Panel(verdict_panel, title="CCK Action Inspection Verdict", border_style=color))

    asyncio.run(_inspect())


@app.command("run-server")
def run_server(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Enable live code reload"),
) -> None:
    """Run the CCK HTTP API server using Uvicorn."""
    import uvicorn

    console.print(f"[bold green]Starting CCK API on http://{host}:{port}...[/bold green]")
    uvicorn.run("cck.api.app:app", host=host, port=port, reload=reload)


@app.command("serve")
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Enable live code reload"),
    shadow: bool = typer.Option(False, "--shadow", help="Run in Observe/Shadow mode (simulate verdicts without blocking)"),
) -> None:
    """Start the CCK API Server and Governance Control Plane."""
    import os

    import uvicorn

    if shadow:
        os.environ["CCK_SHADOW_MODE"] = "true"
        console.print("[bold yellow]Running in SHADOW / OBSERVE Mode: Actions will be evaluated but not physically blocked.[/bold yellow]")

    console.print(f"[bold green]Starting CCK API & Governance Server on http://{host}:{port}...[/bold green]")
    uvicorn.run("cck.api.app:app", host=host, port=port, reload=reload)


@app.command("init")
def init(
    workspace_dir: Path = typer.Option(
        Path("."),
        "--dir",
        "-d",
        help="Target directory to initialize CCK workspace in",
    ),
) -> None:
    """Initialize a new CCK workspace with config, policies, scenarios, and database."""
    async def _init_workspace() -> None:
        target = workspace_dir.resolve()
        policies_dir = target / "policies"
        scenarios_dir = target / "scenarios"
        config_file = target / "cck.config.yaml"
        db_path = target / "cck.db"

        policies_dir.mkdir(parents=True, exist_ok=True)
        scenarios_dir.mkdir(parents=True, exist_ok=True)

        if not config_file.exists():
            config_content = (
                "# CCK (Command & Control Kit) Configuration\n"
                "version: '0.1.0'\n"
                "environment: 'development'\n"
                "storage:\n"
                "  backend: 'sqlite'\n"
                "  path: './cck.db'\n"
                "policy:\n"
                "  default_action: 'REVALIDATE'\n"
                "  risk_threshold: 0.7\n"
                "  shadow_mode: false\n"
                "tamper_evident:\n"
                "  enabled: true\n"
                "telemetry:\n"
                "  enabled: true\n"
            )
            config_file.write_text(config_content, encoding="utf-8")

        # Initialize local storage
        control_plane = CCKControlPlane()
        from cck.storage.sqlite import SQLiteStorageBackend
        control_plane.storage = SQLiteStorageBackend(db_path=db_path)
        await control_plane.initialize()
        policies = await control_plane.list_policies()
        await control_plane.shutdown()

        console.print(
            Panel.fit(
                f"[bold green]✓[/bold green] CCK workspace initialized successfully!\n"
                f" • Config: [cyan]{config_file}[/cyan]\n"
                f" • Database: [cyan]{db_path}[/cyan]\n"
                f" • Policies: [cyan]{policies_dir}[/cyan] ({len(policies)} baseline loaded)\n"
                f" • Scenarios: [cyan]{scenarios_dir}[/cyan]\n\n"
                f"Next steps:\n"
                f" ➜ Run test scenarios: [bold cyan]cck test ./scenarios[/bold cyan]\n"
                f" ➜ Start local server: [bold cyan]cck serve[/bold cyan]",
                title="CCK Initialization Complete",
                border_style="green",
            )
        )

    asyncio.run(_init_workspace())


@app.command("mcp")
def run_mcp_server() -> None:
    """Run CCK as a standard Model Context Protocol (MCP) server over stdio."""
    import sys

    from cck.mcp.server import MCPProxyInterceptor, MCPServerTools

    async def _stdio_mcp() -> None:
        control_plane = CCKControlPlane()
        await control_plane.initialize()
        interceptor = MCPProxyInterceptor(control_plane)

        console.print("[dim]CCK MCP Stdio Server running. Waiting for JSON-RPC messages on stdin...[/dim]", file=sys.stderr)
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
                method = msg.get("method")
                msg_id = msg.get("id")

                if method == "tools/list":
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"tools": MCPServerTools.list_tools()},
                    }
                elif method == "tools/call":
                    params = msg.get("params", {})
                    tool_name = params.get("name", "")
                    tool_args = params.get("arguments", {})
                    verdict = await interceptor.intercept_tool_call(tool_name, tool_args)
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "decision": verdict.decision.value,
                            "reason": verdict.reason,
                            "risk_level": verdict.risk_level.value,
                            "risk_score": verdict.risk_score,
                            "action_id": verdict.action_id,
                        },
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

        await control_plane.shutdown()

    asyncio.run(_stdio_mcp())


@app.command("test")
def test_scenarios(
    scenarios_path: Path = typer.Argument(
        Path("./scenarios"),
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Path to scenarios directory containing JSON test packs",
    ),
) -> None:
    """Run CCK evaluation scenario packs and exit with non-zero code on test failure."""
    from cck.testing.runner import ScenarioRunner

    async def _run() -> None:
        with console.status(f"[bold blue]Running CCK test scenarios from {scenarios_path}..."):
            report = await ScenarioRunner.run_directory(scenarios_path)

        table = Table(title="CCK Testing Lab Evaluation Report", show_header=True, header_style="bold magenta")
        table.add_column("Scenario ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Duration (ms)", style="yellow")
        table.add_column("Result", style="bold")

        for res in report.results:
            status = "[green]PASSED[/green]" if res.passed else f"[red]FAILED: {res.error_message}[/red]"
            table.add_row(res.scenario_id, res.title, f"{res.duration_ms:.2f}", status)

        console.print(table)
        console.print(
            Panel.fit(
                f"Total: [bold]{report.total}[/bold] | Passed: [green]{report.passed}[/green] | Failed: [red]{report.failed}[/red]",
                title="Summary",
                border_style="green" if report.failed == 0 else "red",
            )
        )

        if report.failed > 0:
            raise typer.Exit(code=1)

    asyncio.run(_run())


@app.command("scan")
def scan_local(
    target_path: Path = typer.Argument(
        Path("."),
        exists=True,
        help="Target directory or config file to scan locally (read-only)",
    ),
    output_format: str = typer.Option("summary", "--format", "-f", help="Output format: summary or json"),
) -> None:
    """Run local read-only CCK static scan on MCP/tool/connector manifests without requiring login."""
    import hashlib

    privacy_blocked = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}
    scanned: list[str] = []
    skipped_privacy: list[str] = []
    findings: list[dict[str, str]] = []

    root = target_path.resolve()
    candidates = [root] if root.is_file() else sorted(root.rglob("*.json"))
    for p in candidates:
        name = p.name.lower()
        if any(part in {"node_modules", ".git", "dist", ".venv"} for part in p.parts):
            continue
        if p.name in privacy_blocked or name.endswith((".pem", ".key")):
            skipped_privacy.append(str(p.relative_to(root if root.is_dir() else root.parent)))
            continue
        if name in {"mcp.json", ".mcp.json", "tools.json", "connector.manifest.json", "cck-connector.json"}:
            rel = str(p.relative_to(root if root.is_dir() else root.parent))
            scanned.append(rel)
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                tools = data.get("tools", []) if isinstance(data, dict) else []
                for t in tools:
                    if isinstance(t, dict):
                        perms = t.get("declared_permissions") or t.get("permissions") or []
                        for perm in perms:
                            if str(perm).lower() in {"*", "admin", "root", "shell", "exec"}:
                                findings.append(
                                    {
                                        "rule_id": "CCK-PERM-001",
                                        "severity": "CRITICAL",
                                        "certainty": "CONFIRMED",
                                        "file": rel,
                                        "title": f"Over-privileged permission '{perm}' declared",
                                    }
                                )
            except Exception:
                findings.append(
                    {
                        "rule_id": "CCK-CFG-001",
                        "severity": "LOW",
                        "certainty": "CONFIRMED",
                        "file": rel,
                        "title": "Malformed JSON configuration",
                    }
                )

    report = {
        "scanner_version": "0.3.0-py",
        "mode": "LOCAL",
        "static_analysis_only": True,
        "files_scanned": scanned,
        "files_skipped_privacy": skipped_privacy,
        "findings": findings,
    }
    report["report_digest_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()

    if output_format.lower() == "json":
        typer.echo(json.dumps(report, indent=2))
    else:
        console.print(f"[bold cyan]CCK Local Scan[/bold cyan] | Scanned: {len(scanned)} | Findings: {len(findings)}")
        for f in findings:
            console.print(f" [{f['severity']}] {f['rule_id']} ({f['file']}): {f['title']}")

    if any(f["severity"] == "CRITICAL" for f in findings):
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()

