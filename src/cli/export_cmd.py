"""`kiral export` — Export scan results to file."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from typing import Optional

from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from src.cli.banner import make_banner
from src.cli.theme import PALETTE, console
from src.clickhouse_client import ClickHouseClient
from src.config import settings


def _sanitize_filename(domain: str) -> str:
    return re.sub(r"[^\w\-\.]", "_", domain).strip("_")


async def _export_domain(domain: str, output_path: Optional[str]) -> tuple[int, str]:
    client = ClickHouseClient()
    try:
        query = f"""
        SELECT *
        FROM {settings.ch_database}.events
        WHERE target = '{domain.replace(chr(39), chr(39)+chr(39))}'
        ORDER BY scan_timestamp DESC, event_type, asset
        FORMAT JSONEachRow
        """

        with Progress(
            TextColumn("[kiral.primary]Querying ClickHouse..."),
            BarColumn(style=PALETTE["muted"], complete_style=PALETTE["success"]),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("query", total=None)
            result_text = await client.execute(query, database=settings.ch_database)
            progress.update(task, completed=1)

        lines = [ln for ln in result_text.strip().splitlines() if ln.strip()]
        if not lines:
            return 0, ""

        filename = output_path or f"{_sanitize_filename(domain)}_export.txt"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(f"Domain Export: {domain}\n")
            fh.write(f"Generated at:  {timestamp}\n")
            fh.write(f"Total rows:    {len(lines)}\n")
            fh.write("=" * 60 + "\n\n")

            for idx, line in enumerate(lines, start=1):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    fh.write(f"--- Row {idx} (raw) ---\n{line}\n\n")
                    continue

                fh.write(f"--- Row {idx} ---\n")
                for key in sorted(row.keys()):
                    val = row[key]
                    if key == "data":
                        try:
                            val = json.dumps(json.loads(val), indent=2, ensure_ascii=False)
                        except Exception:
                            pass
                    fh.write(f"{key:20s}: {val}\n")
                fh.write("\n")

        return len(lines), filename
    finally:
        await client.close()


def export_cmd(domain: str, output: Optional[str]) -> None:
    """Export all ClickHouse events for a domain to a text file."""
    console.print(make_banner(compact=True))
    console.print()

    count, filename = asyncio.run(_export_domain(domain, output))

    if count == 0:
        console.print(f"[kiral.warning]No records found for domain '{domain}'.")
        return

    console.print(
        f"[kiral.success]Exported [kiral.bright]{count:,}[/] row(s) to '[kiral.primary]{filename}[/]'."
    )
