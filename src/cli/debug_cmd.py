"""`kiral debug` — Diagnostic tool to check pipeline health for a domain."""

from __future__ import annotations

import asyncio
import json

import redis.asyncio as redis
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import make_banner
from src.cli.theme import PALETTE, console
from src.clickhouse_client import ClickHouseClient
from src.config import settings


async def _check_redis_for_domain(domain: str) -> dict:
    """Check Redis stream for events related to a specific domain."""
    r = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        db=settings.redis_db,
        socket_connect_timeout=5,
    )
    try:
        info = await r.xinfo_stream("asm:events:v1")
        total_depth = int(info.get("length", 0))

        groups = await r.xinfo_groups("asm:events:v1")
        total_pending = 0
        for g in groups:
            total_pending += int(g.get("pending", 0))

        recent = await r.xrange("asm:events:v1", count=100)
        domain_events = 0
        vuln_events = 0
        for _msg_id, fields in recent:
            payload = fields.get(b"payload") or fields.get("payload")
            if payload:
                try:
                    event = json.loads(payload)
                    if event.get("target") == domain:
                        domain_events += 1
                        if event.get("event_type") == "VULNERABILITY_FOUND":
                            vuln_events += 1
                except json.JSONDecodeError:
                    pass

        return {
            "stream_depth": total_depth,
            "pending": total_pending,
            "recent_for_domain": domain_events,
            "recent_vulns": vuln_events,
        }
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        await r.aclose()


async def _check_clickhouse_for_domain(domain: str) -> dict:
    """Check ClickHouse for events by type for a specific domain."""
    client = ClickHouseClient()
    try:
        query = f"""
        SELECT
            event_type,
            count()
        FROM {settings.ch_database}.events
        WHERE target = '{domain.replace(chr(39), chr(39)+chr(39))}'
        GROUP BY event_type
        FORMAT JSONEachRow
        """
        result = await client.execute(query, database=settings.ch_database)
        counts = {}
        for line in result.strip().splitlines():
            if line.strip():
                row = json.loads(line)
                counts[row["event_type"]] = int(row["count()"])

        vuln_query = f"""
        SELECT count()
        FROM {settings.ch_database}.events
        WHERE target = '{domain.replace(chr(39), chr(39)+chr(39))}'
          AND event_type = 'VULNERABILITY_FOUND'
        FORMAT JSONEachRow
        """
        vuln_result = await client.execute(vuln_query, database=settings.ch_database)
        vuln_count = 0
        for line in vuln_result.strip().splitlines():
            if line.strip():
                row = json.loads(line)
                vuln_count = int(row["count()"])

        return {"counts": counts, "vuln_count": vuln_count}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        await client.close()


def debug_cmd(domain: str) -> None:
    """Debug pipeline state for a specific domain."""
    console.print(make_banner(compact=True))
    console.print()
    console.print(f"[kiral.primary]Debugging pipeline for domain: {domain}[/]")
    console.print()

    redis_info = asyncio.run(_check_redis_for_domain(domain))
    ch_info = asyncio.run(_check_clickhouse_for_domain(domain))

    # Redis panel
    if "error" in redis_info:
        redis_panel = Panel(
            f"[kiral.error]{redis_info['error']}[/]",
            title="[kiral.error]Redis",
            border_style=PALETTE["error"],
        )
    else:
        redis_table = Table(show_header=False, box=None, padding=(0, 1))
        redis_table.add_column(style=f"bold {PALETTE['primary']}")
        redis_table.add_column(style=PALETTE["bright"])
        redis_table.add_row("Stream Depth", f"{redis_info['stream_depth']:,}")
        redis_table.add_row("Pending (un-ACKed)", f"{redis_info['pending']:,}")
        redis_table.add_row("Recent events for domain", f"{redis_info['recent_for_domain']:,}")
        redis_table.add_row("Recent vulns in stream", f"{redis_info['recent_vulns']:,}")

        redis_panel = Panel(
            redis_table,
            title="[kiral.primary]Redis Stream",
            border_style=PALETTE["primary"],
            padding=(1, 2),
        )

    # ClickHouse panel
    if "error" in ch_info:
        ch_panel = Panel(
            f"[kiral.error]{ch_info['error']}[/]",
            title="[kiral.error]ClickHouse",
            border_style=PALETTE["error"],
        )
    else:
        ch_table = Table(show_header=False, box=None, padding=(0, 1))
        ch_table.add_column(style=f"bold {PALETTE['primary']}")
        ch_table.add_column(style=PALETTE["bright"])

        counts = ch_info.get("counts", {})
        if counts:
            for etype, count in sorted(counts.items()):
                ch_table.add_row(etype, f"{count:,}")
        else:
            ch_table.add_row("No events found", "—")

        ch_table.add_row("", "")
        ch_table.add_row(
            "VULNERABILITY_FOUND",
            Text(str(ch_info.get("vuln_count", 0)), style=f"bold {PALETTE['error']}"),
        )

        ch_panel = Panel(
            ch_table,
            title="[kiral.primary]ClickHouse",
            border_style=PALETTE["primary"],
            padding=(1, 2),
        )

    console.print(redis_panel)
    console.print()
    console.print(ch_panel)
    console.print()

    # Diagnosis
    vulns_in_redis = redis_info.get("recent_vulns", 0) if "error" not in redis_info else 0
    vulns_in_ch = ch_info.get("vuln_count", 0) if "error" not in ch_info else 0

    if vulns_in_ch > 0:
        console.print(f"[kiral.success]✓ Found {vulns_in_ch} vulnerability(ies) in ClickHouse.[/]")
        console.print(f"[kiral.muted]Run: kiral vulns {domain}[/]")
    elif vulns_in_redis > 0:
        console.print("[kiral.warning]⚠ Vulnerabilities are in Redis but NOT in ClickHouse.[/]")
        console.print("[kiral.muted]The consumer is likely not running. Start it with:[/]")
        console.print("[kiral.primary]  docker run -d --name asm-consumer --network host ...[/]")
    else:
        console.print("[kiral.warning]No vulnerabilities found in Redis or ClickHouse.[/]")
        console.print(f"[kiral.muted]Run a scan first: kiral scan {domain}[/]")
