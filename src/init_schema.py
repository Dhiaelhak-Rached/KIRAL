"""Initialize ClickHouse database and tables.

Requires an admin-privileged user (e.g., 'default') because DDL
(CREATE DATABASE / CREATE TABLE) needs elevated grants.
The pipeline consumer uses the restricted asm_ingestor account.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from src.clickhouse_client import ClickHouseClient
from src.config import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

CREATE_DATABASE_SQL = "CREATE DATABASE IF NOT EXISTS {db}"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS {db}.events (
    event_id UUID,
    event_type LowCardinality(String),
    target String,
    asset String,
    source_tool LowCardinality(String),
    scan_id UUID,
    scan_timestamp DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    data String CODEC(ZSTD(3)),
    producer_host LowCardinality(String),
    producer_version LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_timestamp)
ORDER BY (event_type, target, scan_timestamp, asset)
TTL scan_timestamp + INTERVAL 12 MONTH
SETTINGS index_granularity = 8192
"""


async def init_schema(user: str = "default", password: str | None = None) -> None:
    """Initialize ClickHouse database and tables.

    Args:
        user: Admin username with DDL privileges.
        password: Admin password.
    """
    client = ClickHouseClient(
        username=user,
        password=password or None,
    )
    try:
        logger.info(
            f"Initializing schema as user={user} in database={settings.ch_database}"
        )
        await client.execute(
            CREATE_DATABASE_SQL.format(db=settings.ch_database)
        )
        await client.execute(
            CREATE_TABLE_SQL.format(db=settings.ch_database),
            database=settings.ch_database,
        )
        logger.info("Schema initialized successfully")
    except Exception as exc:
        logger.error(f"Schema initialization failed: {exc}")
        raise
    finally:
        await client.close()


async def main():
    parser = argparse.ArgumentParser(
        description="Initialize ClickHouse schema (one-time admin operation)"
    )
    parser.add_argument(
        "--user",
        default="default",
        help="Admin username with DDL privileges (default: default)",
    )
    parser.add_argument(
        "--password",
        default="",
        help="Admin password (default: empty)",
    )
    args = parser.parse_args()
    await init_schema(user=args.user, password=args.password or None)


if __name__ == "__main__":
    asyncio.run(main())
