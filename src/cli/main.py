"""KIRAL CLI entry point — Typer app with all commands."""

from __future__ import annotations

from typing import Optional

import typer

from src.cli.banner import make_banner
from src.cli.theme import console

app = typer.Typer(
    name="kiral",
    help="KIRAL — Attack Surface Intelligence Terminal",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #
@app.command(rich_help_panel="Operations")
def scan(
    domain: str = typer.Argument(..., help="Target domain to scan (e.g. example.com)"),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Scan profile: stealth or aggressive"),
) -> None:
    """Launch a full reconnaissance scan with live dashboard."""
    from src.cli.scan_cmd import scan_cmd
    scan_cmd(domain, profile)


@app.command(rich_help_panel="Operations")
def status() -> None:
    """Check health of all KIRAL components."""
    from src.cli.status_cmd import status_cmd
    status_cmd()


@app.command(rich_help_panel="Operations")
def init(
    user: str = typer.Option("asm_ingestor", "--user", "-u", help="ClickHouse user with DDL grants"),
    password: str = typer.Option("changeme", "--password", "-p", help="ClickHouse password"),
) -> None:
    """Initialize the ClickHouse database and events table."""
    from src.cli.init_cmd import init_cmd
    init_cmd(user, password)


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #
@app.command(rich_help_panel="Data")
def query(
    domain: str = typer.Argument(..., help="Target domain to query"),
    event_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by event type"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max rows to return"),
) -> None:
    """Query ClickHouse for scan results and display in a rich table."""
    from src.cli.query_cmd import query_cmd
    query_cmd(domain, event_type, limit)


@app.command(rich_help_panel="Data")
def export(
    domain: str = typer.Argument(..., help="Target domain to export"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Export all ClickHouse events for a domain to a text file."""
    from src.cli.export_cmd import export_cmd
    export_cmd(domain, output)


@app.command(rich_help_panel="Data")
def vulns(
    domain: str = typer.Argument(..., help="Target domain to inspect"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity: critical, high, medium, low, info"),
    limit: int = typer.Option(100, "--limit", "-n", help="Max rows to return"),
) -> None:
    """Display vulnerability findings for a scanned domain."""
    from src.cli.vulns_cmd import vulns_cmd
    vulns_cmd(domain, severity, limit)


# --------------------------------------------------------------------------- #
# Monitoring
# --------------------------------------------------------------------------- #
@app.command(rich_help_panel="Monitoring")
def dashboard(
    refresh: int = typer.Option(2, "--refresh", "-r", help="Refresh interval in seconds"),
) -> None:
    """Launch a live monitoring dashboard for the pipeline."""
    from src.cli.dashboard_cmd import dashboard_cmd
    dashboard_cmd(refresh)


@app.command(rich_help_panel="Monitoring")
def debug(
    domain: str = typer.Argument(..., help="Target domain to debug"),
) -> None:
    """Debug pipeline state for a specific domain (Redis vs ClickHouse)."""
    from src.cli.debug_cmd import debug_cmd
    debug_cmd(domain)


if __name__ == "__main__":
    app()
