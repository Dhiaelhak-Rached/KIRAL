"""`kiral query` — Query ClickHouse results in rich tables."""

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


async def _query_clickhouse(
    domain: str,
    event_type: Optional[str],
    limit: int,
) -> list[dict]:
    client = ClickHouseClient()
    try:
        if not isinstance(limit, int) or limit < 1 or limit > 10_000:
            raise ValueError("limit must be an integer between 1 and 10,000")

        type_filter = ""
        query_params: dict[str, str] = {"domain": domain, "limit": str(limit)}
        if event_type:
            type_filter = "AND event_type = {event_type:String}"
            query_params["event_type"] = event_type

        query = f"""
        SELECT
            event_type,
            asset,
            source_tool,
            scan_timestamp,
            data
        FROM {settings.ch_database}.events
        WHERE target = {{domain:String}}
        {type_filter}
        ORDER BY scan_timestamp DESC
        LIMIT {{limit:UInt32}}
        FORMAT JSONEachRow
        """
        result = await client.execute(
            query, database=settings.ch_database, query_params=query_params
        )
        rows = []
        for line in result.strip().splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows
    finally:
        await client.close()


def query_cmd(domain: str, event_type: Optional[str], limit: int) -> None:
    """Query ClickHouse for scan results and display in a rich table."""
    console.print(make_banner(compact=True))
    console.print()

    rows = asyncio.run(_query_clickhouse(domain, event_type, limit))

    if not rows:
        console.print(f"[kiral.warning]No records found for domain '{domain}'.")
        return

    table = Table(
        title=f"[kiral.primary]Results for {domain}",
        box=box.ROUNDED,
        border_style=PALETTE["primary"],
        expand=True,
    )
    table.add_column("#", justify="right", style=PALETTE["muted"])
    table.add_column("Event Type", style=f"bold {PALETTE['primary']}")
    table.add_column("Asset", style=PALETTE["bright"])
    table.add_column("Tool", style=PALETTE["accent"])
    table.add_column("Data", overflow="fold")

    for idx, row in enumerate(rows, start=1):
        data_str = row.get("data", "")
        try:
            data_pretty = json.dumps(json.loads(data_str), indent=2, ensure_ascii=False)
        except Exception:
            data_pretty = data_str

        if len(data_pretty) > 300:
            data_pretty = data_pretty[:300] + "\n... [truncated]"

        table.add_row(
            str(idx),
            row.get("event_type", ""),
            row.get("asset", ""),
            row.get("source_tool", ""),
            Text(data_pretty, style=PALETTE["muted"]),
        )

    console.print(table)
    console.print(f"\n[kiral.muted]Showing {len(rows)} row(s).[/]")
