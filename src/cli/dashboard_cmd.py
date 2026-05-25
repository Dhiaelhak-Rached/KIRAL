"""`kiral dashboard` — Live pipeline monitor."""

from __future__ import annotations

import asyncio
import json
import time

import redis.asyncio as redis
from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import make_banner
from src.cli.theme import PALETTE, console
from src.clickhouse_client import ClickHouseClient
from src.config import settings


async def _get_redis_depth(r: redis.Redis) -> int:
    try:
        info = await r.xinfo_stream("asm:events:v1")
        return int(info.get("length", 0))
    except Exception:
        return 0


async def _get_consumer_lag(r: redis.Redis) -> int:
    try:
        groups = await r.xinfo_groups("asm:events:v1")
        total_pending = 0
        for g in groups:
            total_pending += int(g.get("pending", 0))
        return total_pending
    except Exception:
        return 0


async def _get_clickhouse_counts() -> dict[str, int]:
    client = ClickHouseClient()
    try:
        result = await client.execute(
            f"SELECT event_type, count() FROM {settings.ch_database}.events GROUP BY event_type FORMAT JSONEachRow",
            database=settings.ch_database,
        )
        counts = {}
        for line in result.strip().splitlines():
            if line.strip():
                row = json.loads(line)
                counts[row["event_type"]] = int(row["count()"])
        return counts
    except Exception:
        return {}
    finally:
        await client.close()


async def _get_recent_events(limit: int = 15) -> list[dict]:
    client = ClickHouseClient()
    try:
        result = await client.execute(
            f"""
            SELECT event_type, asset, source_tool, scan_timestamp
            FROM {settings.ch_database}.events
            ORDER BY scan_timestamp DESC
            LIMIT {limit}
            FORMAT JSONEachRow
            """,
            database=settings.ch_database,
        )
        rows = []
        for line in result.strip().splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    except Exception:
        return []
    finally:
        await client.close()


def _render_dashboard(
    stream_depth: int,
    pending: int,
    ch_counts: dict[str, int],
    recent: list[dict],
) -> Panel:
    left_table = Table(show_header=False, box=None, padding=(0, 1))
    left_table.add_column(style=f"bold {PALETTE['primary']}")
    left_table.add_column(style=PALETTE["bright"])

    left_table.add_row("Redis Stream Depth", f"{stream_depth:,}")
    left_table.add_row("Consumer Pending", f"{pending:,}")
    left_table.add_row("", "")

    total_rows = sum(ch_counts.values())
    left_table.add_row("ClickHouse Total", f"{total_rows:,}")
    for etype, count in sorted(ch_counts.items()):
        left_table.add_row(f"  {etype}", f"{count:,}")

    left_panel = Panel(
        left_table,
        title="[kiral.primary]Pipeline Stats",
        border_style=PALETTE["primary"],
        padding=(1, 2),
    )

    right_table = Table(show_header=True, box=box.ROUNDED, border_style=PALETTE["accent"], expand=True)
    right_table.add_column("Time", style=PALETTE["muted"], max_width=19)
    right_table.add_column("Type", style=f"bold {PALETTE['primary']}", max_width=18)
    right_table.add_column("Asset", style=PALETTE["bright"])
    right_table.add_column("Tool", style=PALETTE["accent"], max_width=10)

    for row in recent:
        ts = str(row.get("scan_timestamp", ""))
        if "." in ts:
            ts = ts[: ts.index(".")]
        right_table.add_row(
            ts,
            row.get("event_type", ""),
            row.get("asset", ""),
            row.get("source_tool", ""),
        )

    right_panel = Panel(
        right_table,
        title="[kiral.accent]Recent Events",
        border_style=PALETTE["accent"],
        padding=(1, 2),
    )

    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=2)
    grid.add_row(left_panel, right_panel)

    return Panel(
        grid,
        title=f"[kiral.primary]KIRAL Dashboard  [kiral.muted]{time.strftime('%H:%M:%S')}[/]",
        border_style=PALETTE["primary"],
        padding=(1, 2),
    )


def dashboard_cmd(refresh: int) -> None:
    """Launch a live monitoring dashboard for the pipeline."""
    console.print(make_banner(compact=True))
    console.print()
    console.print("[kiral.muted]Press Ctrl+C to exit.[/]")
    console.print()

    async def _loop() -> None:
        r = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            socket_connect_timeout=5,
        )
        try:
            with Live(console=console, refresh_per_second=2, screen=True) as live:
                while True:
                    stream_depth = await _get_redis_depth(r)
                    pending = await _get_consumer_lag(r)
                    ch_counts = await _get_clickhouse_counts()
                    recent = await _get_recent_events()
                    live.update(_render_dashboard(stream_depth, pending, ch_counts, recent))
                    await asyncio.sleep(refresh)
        finally:
            await r.aclose()

    try:
        asyncio.run(_loop())
    except KeyboardInterrupt:
        console.print("\n[kiral.muted]Dashboard stopped.[/]")
