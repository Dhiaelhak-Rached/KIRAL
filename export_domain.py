"""Temporary script: export all ClickHouse events for a given domain to a text file."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime

from src.clickhouse_client import ClickHouseClient
from src.config import settings


def sanitize_filename(domain: str) -> str:
    """Make a filesystem-safe filename from a domain."""
    return re.sub(r"[^\w\-\.]", "_", domain).strip("_")


def pretty_json(raw: str) -> str:
    """Pretty-print a JSON string; fallback to raw if invalid."""
    try:
        return json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
    except Exception:
        return raw


async def export_domain(domain: str, output_path: str | None = None) -> None:
    client = ClickHouseClient()
    try:
        # Query every row for this target domain
        query = f"""
        SELECT
            event_id,
            event_type,
            target,
            asset,
            source_tool,
            scan_id,
            scan_timestamp,
            ingested_at,
            data,
            producer_host,
            producer_version
        FROM {settings.ch_database}.events
        WHERE target = '{domain.replace(chr(39), chr(39)+chr(39))}'
        ORDER BY scan_timestamp DESC, event_type, asset
        FORMAT JSONEachRow
        """

        print(f"Querying ClickHouse for domain: {domain} ...")
        result_text = await client.execute(query, database=settings.ch_database)

        lines = [ln for ln in result_text.strip().splitlines() if ln.strip()]
        if not lines:
            print(f"No records found for domain '{domain}'.")
            return

        filename = output_path or f"{sanitize_filename(domain)}_export.txt"
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
                fh.write(f"event_id:            {row.get('event_id')}\n")
                fh.write(f"event_type:          {row.get('event_type')}\n")
                fh.write(f"target:              {row.get('target')}\n")
                fh.write(f"asset:               {row.get('asset')}\n")
                fh.write(f"source_tool:         {row.get('source_tool')}\n")
                fh.write(f"scan_id:             {row.get('scan_id')}\n")
                fh.write(f"scan_timestamp:      {row.get('scan_timestamp')}\n")
                fh.write(f"ingested_at:         {row.get('ingested_at')}\n")
                fh.write(f"producer_host:       {row.get('producer_host')}\n")
                fh.write(f"producer_version:    {row.get('producer_version')}\n")
                fh.write("data:\n")
                fh.write(pretty_json(row.get("data", "")))
                fh.write("\n\n")

        print(f"Exported {len(lines)} row(s) to '{filename}'.")
    finally:
        await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export all ClickHouse events for a specific domain to a text file."
    )
    parser.add_argument("domain", help="Target domain to look up (e.g. example.com)")
    parser.add_argument(
        "-o", "--output", default=None, help="Output file path (default: <domain>_export.txt)"
    )
    args = parser.parse_args()

    asyncio.run(export_domain(args.domain, args.output))


if __name__ == "__main__":
    main()
