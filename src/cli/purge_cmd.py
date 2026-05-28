"""`kiral purge` — Remove a domain's scan data from ClickHouse and Redis."""

from __future__ import annotations

import asyncio
from typing import Optional

import redis.asyncio as redis
from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import make_banner
from src.cli.theme import PALETTE, console
from src.clickhouse_client import ClickHouseClient
from src.config import settings


async def _count_domain_rows(domain: str) -> int:
    """Count how many rows exist for this domain in ClickHouse."""
    client = ClickHouseClient()
    try:
        query = f"""
        SELECT count()
        FROM {settings.ch_database}.events
        WHERE target = {{domain:String}}
        FORMAT JSONEachRow
        """
        result = await client.execute(
            query,
            database=settings.ch_database,
            query_params={"domain": domain},
        )
        for line in result.strip().splitlines():
            if line.strip():
                import json
                return int(json.loads(line)["count()"])
        return 0
    finally:
        await client.close()


async def _purge_clickhouse(domain: str, username: str, password: Optional[str]) -> None:
    """Execute ALTER DELETE to remove all rows for the domain."""
    client = ClickHouseClient(
        username=username,
        password=password,
    )
    try:
        query = f"""
        ALTER TABLE {settings.ch_database}.events
        DELETE WHERE target = {{domain:String}}
        """
        await client.execute(
            query,
            database=settings.ch_database,
            query_params={"domain": domain},
        )
    finally:
        await client.close()


async def _purge_redis_dedup() -> int:
    """Delete the entire Redis dedup set. Returns number of elements removed."""
    r = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        db=settings.redis_db,
        socket_connect_timeout=5,
    )
    try:
        count = await r.scard("asm:dedup:seen")
        await r.delete("asm:dedup:seen")
        return count
    finally:
        await r.aclose()


def purge_cmd(
    domain: str,
    force: bool,
    full: bool,
    ch_user: Optional[str],
    ch_password: Optional[str],
) -> None:
    """Remove all scan data for a specific domain."""
    console.print(make_banner(compact=True))
    console.print()

    target = domain.strip().lower()

    # Fetch row count
    row_count = asyncio.run(_count_domain_rows(target))

    # Build warning panel
    warning_text = Text.assemble(
        Text("You are about to permanently delete all scan data for:\n\n", style=PALETTE["bright"]),
        Text(f"  Domain:  {target}\n", style=f"bold {PALETTE['error']}"),
        Text(f"  Rows:    {row_count:,} in ClickHouse\n", style=PALETTE["warning"]),
    )

    if full:
        warning_text.append(
            "\n  --full flag: This will also clear the entire Redis dedup cache.\n",
            style=f"bold {PALETTE['error']}",
        )
        warning_text.append(
            "  This affects ALL domains, not just this one.\n",
            style=PALETTE["muted"],
        )

    warning_text.append(
        "\nThis action is irreversible. The data cannot be recovered.\n",
        style=PALETTE["muted"],
    )

    warning_text.append(
        "\nNote: ClickHouse ALTER DELETE runs asynchronously in the background.\n"
        "Rows may not disappear instantly — they are removed during the next merge.",
        style=PALETTE["muted"],
    )

    panel = Panel(
        Align.center(warning_text),
        title="[kiral.error]⚠ DESTRUCTIVE OPERATION",
        border_style=PALETTE["error"],
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    if not force:
        confirm = console.input(
            f"Type the domain name ([kiral.primary]{target}[/]) to confirm: "
        )
        if confirm.strip().lower() != target:
            console.print("\n[kiral.error]Confirmation failed. Aborted.[/]")
            raise SystemExit(1)

    # Determine ClickHouse credentials
    delete_user = ch_user or settings.ch_user
    delete_password = ch_password or settings.ch_password

    # Execute ClickHouse purge
    try:
        asyncio.run(_purge_clickhouse(target, delete_user, delete_password))
        console.print(
            f"\n[kiral.success]✓ ClickHouse DELETE scheduled for '{target}'."
        )
        console.print(
            f"[kiral.muted]  {row_count:,} row(s) will be removed during the next merge.[/]"
        )
    except Exception as exc:
        console.print(f"\n[kiral.error]ClickHouse purge failed: {exc}[/]")
        console.print(
            "[kiral.muted]Hint: ALTER DELETE may require a user with elevated privileges.\n"
            "Try: kiral purge example.com --ch-user default --ch-password <admin-pass>[/]"
        )
        raise SystemExit(1)

    # Execute Redis dedup purge if requested
    if full:
        try:
            dedup_count = asyncio.run(_purge_redis_dedup())
            console.print(
                f"\n[kiral.success]✓ Redis dedup cache cleared ({dedup_count:,} hash(es) removed)."
            )
        except Exception as exc:
            console.print(f"\n[kiral.warning]Redis dedup clear failed: {exc}[/]")

    console.print()
    console.print(
        Panel(
            Text.assemble(
                Text("Next steps:\n", style=f"bold {PALETTE['bright']}"),
                Text("1. Re-scan the domain: ", style=PALETTE["muted"]),
                Text(f"kiral scan {target}\n", style=PALETTE["primary"]),
                Text("2. Monitor deletion progress in ClickHouse:\n", style=PALETTE["muted"]),
                Text(
                    f"   SELECT count() FROM {settings.ch_database}.events WHERE target = {{{{target:String}}}}\n",
                    style=PALETTE["primary"],
                ),
            ),
            border_style=PALETTE["success"],
            padding=(1, 2),
        )
    )
