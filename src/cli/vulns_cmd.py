"""`kiral vulns` — Display vulnerability findings for a scanned domain."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import make_banner
from src.cli.theme import PALETTE, console
from src.clickhouse_client import ClickHouseClient
from src.config import settings


SEVERITY_COLORS = {
    "critical": PALETTE["error"],
    "high": "#ff6b35",
    "medium": PALETTE["warning"],
    "low": PALETTE["success"],
    "info": PALETTE["primary"],
    "unknown": PALETTE["muted"],
}


def severity_badge(severity: str) -> Text:
    """Return a color-coded severity badge."""
    color = SEVERITY_COLORS.get(severity.lower(), PALETTE["muted"])
    return Text(f" {severity.upper()} ", style=f"bold {color}")


def _severity_rank(severity: str) -> int:
    """Return numeric rank for sorting by severity."""
    ranks = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    return ranks.get(severity.lower(), 6)


async def _fetch_vulns(domain: str, severity_filter: Optional[str], limit: int) -> list[dict]:
    """Query ClickHouse for VULNERABILITY_FOUND events and parse data JSON in Python."""
    client = ClickHouseClient()
    try:
        if not isinstance(limit, int) or limit < 1 or limit > 10_000:
            raise ValueError("limit must be an integer between 1 and 10,000")

        query = f"""
        SELECT
            asset,
            data
        FROM {settings.ch_database}.events
        WHERE target = {{domain:String}}
          AND event_type = 'VULNERABILITY_FOUND'
        ORDER BY scan_timestamp DESC
        LIMIT {{limit:UInt32}}
        FORMAT JSONEachRow
        """
        result = await client.execute(
            query,
            database=settings.ch_database,
            query_params={"domain": domain, "limit": str(limit)},
        )
        rows = []
        for line in result.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                # Parse the nested data JSON string into a dict
                data_str = row.get("data", "")
                if data_str:
                    data = json.loads(data_str)
                else:
                    data = {}
                rows.append({
                    "asset": row.get("asset", ""),
                    "template_id": data.get("template_id", ""),
                    "name": data.get("name", ""),
                    "severity": data.get("severity", "unknown"),
                    "matched_at": data.get("matched_at", ""),
                    "tags": data.get("tags", []) or [],
                    "matcher_name": data.get("matcher_name", ""),
                    "type": data.get("type", ""),
                })
            except (json.JSONDecodeError, KeyError):
                continue

        # Apply severity filter in Python
        if severity_filter:
            rows = [r for r in rows if r["severity"].lower() == severity_filter.lower()]

        # Sort by severity rank, then asset
        rows.sort(key=lambda r: (_severity_rank(r["severity"]), r["asset"]))
        return rows
    finally:
        await client.close()


def _build_summary(vulns: list[dict]) -> Panel:
    """Build a summary panel with severity counts."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for v in vulns:
        sev = v.get("severity", "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style=f"bold {PALETTE['muted']}")
    table.add_column()

    total = sum(counts.values())
    table.add_row("Total", Text(str(total), style=f"bold {PALETTE['bright']}"))
    table.add_row("", "")

    for sev in ("critical", "high", "medium", "low", "info"):
        if counts[sev] > 0:
            table.add_row(
                sev.capitalize(),
                Text(str(counts[sev]), style=f"bold {SEVERITY_COLORS[sev]}"),
            )

    return Panel(
        table,
        title="[kiral.error]Vulnerability Summary",
        border_style=PALETTE["error"],
        padding=(1, 2),
    )


def _build_vuln_table(vulns: list[dict]) -> Table:
    """Build a rich table of vulnerabilities."""
    table = Table(
        title="[kiral.error]Vulnerability Details",
        box=box.ROUNDED,
        border_style=PALETTE["error"],
        expand=True,
        row_styles=[None, "dim"],
    )

    table.add_column("Severity", max_width=10)
    table.add_column("Template ID", style=f"bold {PALETTE['accent']}", max_width=28)
    table.add_column("Name", style=f"bold {PALETTE['bright']}", min_width=25)
    table.add_column("Asset", style=PALETTE["primary"])
    table.add_column("Matched At", overflow="fold")

    for v in vulns:
        sev = v.get("severity", "unknown").lower()
        badge = severity_badge(sev)

        matched = v.get("matched_at", "")
        if matched == v.get("asset", ""):
            matched = "—"

        # Truncate name if too long
        name = v.get("name", "") or "Unnamed"
        if len(name) > 50:
            name = name[:47] + "..."

        table.add_row(
            badge,
            v.get("template_id", "") or "—",
            name,
            v.get("asset", "") or "—",
            matched,
        )

    return table


def vulns_cmd(domain: str, severity: Optional[str], limit: int) -> None:
    """Display vulnerability findings for a scanned domain."""
    console.print(make_banner(compact=True))
    console.print()

    vulns = asyncio.run(_fetch_vulns(domain, severity, limit))

    if not vulns:
        if severity:
            console.print(
                f"[kiral.warning]No [kiral.error]{severity.upper()}[/] vulnerabilities found for '{domain}'."
            )
        else:
            console.print(
                f"[kiral.warning]No vulnerabilities found for domain '{domain}'.\n"
                f"[kiral.muted]Run a scan first: kiral scan {domain}[/]"
            )
        return

    # Summary panel
    console.print(_build_summary(vulns))
    console.print()

    # Details table
    console.print(_build_vuln_table(vulns))
    console.print()

    # Footer
    footer = Text.assemble(
        Text("Showing ", style=PALETTE["muted"]),
        Text(str(len(vulns)), style=f"bold {PALETTE['bright']}"),
        Text(" vulnerability finding(s) for ", style=PALETTE["muted"]),
        Text(domain, style=f"bold {PALETTE['primary']}"),
    )
    if severity:
        footer.append(" (filtered by ", style=PALETTE["muted"])
        footer.append(severity.upper(), style=f"bold {PALETTE['error']}")
        footer.append(")", style=PALETTE["muted"])
    console.print(footer)
