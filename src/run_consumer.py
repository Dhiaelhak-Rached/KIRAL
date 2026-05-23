"""Standalone consumer entry point.

Runs the Redis→ClickHouse ingester. Intended for execution on the
remote server (via Docker or directly) or on the laptop.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import redis.asyncio as redis

from src.clickhouse_client import ClickHouseClient
from src.config import settings
from src.consumer import ClickHouseIngester, StreamConsumer

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


async def main():
    redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        db=settings.redis_db,
        socket_connect_timeout=10,
        socket_keepalive=True,
        health_check_interval=30,
    )

    ch_client = ClickHouseClient()
    consumer = StreamConsumer(
        redis_client,
        batch_size=min(settings.batch_size, 1_000),  # Redis read smaller than CH batch
        block_ms=5_000,
    )
    ingester = ClickHouseIngester(
        consumer,
        ch_client,
        batch_size=settings.batch_size,
        flush_interval=settings.flush_interval,
    )

    try:
        await ingester.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
        await ingester.stop()
    finally:
        await redis_client.aclose()
        await ch_client.close()
        logger.info(f"Consumer stats: {ingester.stats}")


if __name__ == "__main__":
    asyncio.run(main())
