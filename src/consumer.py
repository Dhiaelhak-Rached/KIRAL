"""Redis Streams consumer and ClickHouse ingester.

Runs on the remote server (or laptop) to drain the Redis Stream
and batch-insert into ClickHouse.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

import redis.asyncio as redis

from src.clickhouse_client import ClickHouseClient

logger = logging.getLogger(__name__)


class StreamConsumer:
    """Reads from a Redis Stream via consumer groups."""

    def __init__(
        self,
        redis_client: redis.Redis,
        consumer_group: str = "ch_ingestors",
        consumer_name: str = "worker-0",
        batch_size: int = 1_000,
        block_ms: int = 5_000,
    ):
        self.r = redis_client
        self.group = consumer_group
        self.name = consumer_name
        self.stream_key = "asm:events:v1"
        self.batch_size = batch_size
        self.block_ms = block_ms
        self._stopped = False

    async def ensure_group(self):
        """Create the consumer group if it does not exist."""
        try:
            await self.r.xgroup_create(
                self.stream_key, self.group, id="0", mkstream=True
            )
            logger.info(f"Created consumer group {self.group}")
        except redis.ResponseError as exc:
            if "already exists" not in str(exc):
                raise

    async def read_batch(self) -> list[tuple[str, dict]]:
        """Read a batch of messages from the stream.

        Returns:
            List of (msg_id, payload_dict) tuples.
        """
        if self._stopped:
            return []

        resp = await self.r.xreadgroup(
            groupname=self.group,
            consumername=self.name,
            streams={self.stream_key: ">"},
            count=self.batch_size,
            block=self.block_ms,
        )

        results: list[tuple[str, dict]] = []
        if not resp:
            return results

        for _stream_name, entries in resp:
            for msg_id, fields in entries:
                payload = fields.get(b"payload") or fields.get("payload")
                if not payload:
                    continue

                msg_id_str = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                try:
                    data = json.loads(payload)
                    results.append((msg_id_str, data))
                except json.JSONDecodeError:
                    logger.error(f"Corrupted JSON in stream, ACKing: {msg_id_str}")
                    await self.r.xack(self.stream_key, self.group, msg_id_str)

        return results

    async def ack(self, msg_ids: list[str]):
        """Acknowledge messages so they are removed from the PEL."""
        if msg_ids:
            await self.r.xack(self.stream_key, self.group, *msg_ids)

    async def recover_pending(
        self, idle_min_ms: int = 60_000
    ) -> list[tuple[str, dict]]:
        """Claim messages that have been idle in the PEL.

        Used on startup to recover work from a crashed consumer.
        """
        try:
            pending = await self.r.xpending_range(
                self.stream_key, self.group,
                min="-", max="+", count=100
            )
            if not pending:
                return []

            to_claim: list[str] = []
            for item in pending:
                idle = item.get("time_since_delivered", 0)
                if idle > idle_min_ms:
                    mid = item["message_id"]
                    mid_str = mid.decode() if isinstance(mid, bytes) else mid
                    to_claim.append(mid_str)

            if not to_claim:
                return []

            claimed = await self.r.xclaim(
                self.stream_key, self.group, self.name,
                min_idle_time=idle_min_ms, message_ids=to_claim
            )

            results: list[tuple[str, dict]] = []
            for msg_id, fields in claimed:
                payload = fields.get(b"payload") or fields.get("payload")
                if not payload:
                    continue
                msg_id_str = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                try:
                    data = json.loads(payload)
                    results.append((msg_id_str, data))
                except json.JSONDecodeError:
                    await self.r.xack(self.stream_key, self.group, msg_id_str)

            if results:
                logger.info(f"Recovered {len(results)} pending messages")
            return results
        except Exception as exc:
            logger.error(f"Failed to recover pending messages: {exc}")
            return []

    def stop(self):
        self._stopped = True


class ClickHouseIngester:
    """Consumes Redis Stream events and batch-flushes to ClickHouse."""

    def __init__(
        self,
        consumer: StreamConsumer,
        ch_client: ClickHouseClient,
        batch_size: int = 5_000,
        flush_interval: float = 5.0,
        max_retries: int = 3,
    ):
        self.consumer = consumer
        self.ch = ch_client
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self._buffer: list[dict] = []
        self._pending_ids: list[str] = []
        self._running = False
        self._flushes = 0
        self._errors = 0

    async def run(self):
        """Main consumer loop. Blocks forever until stopped."""
        await self.consumer.ensure_group()
        self._running = True
        last_flush = time.time()
        logger.info("Ingester started")

        # Recover work from previous crash
        recovered = await self.consumer.recover_pending()
        for msg_id, event in recovered:
            self._add_to_buffer(msg_id, event)

        while self._running:
            try:
                messages = await self.consumer.read_batch()
                for msg_id, event in messages:
                    self._add_to_buffer(msg_id, event)

                now = time.time()
                should_flush = (
                    len(self._buffer) >= self.batch_size
                    or (now - last_flush) >= self.flush_interval
                )
                if should_flush:
                    await self._flush()
                    last_flush = now

            except Exception as exc:
                logger.exception(f"Ingester loop error: {exc}")
                await asyncio.sleep(1)

        # Final flush on graceful shutdown
        await self._flush()
        logger.info("Ingester stopped")

    def _add_to_buffer(self, msg_id: str, event: dict):
        """Convert a canonical event into a flat ClickHouse row."""
        meta = event.get("metadata", {})
        row = {
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "target": event.get("target"),
            "asset": event.get("asset"),
            "source_tool": event.get("source_tool"),
            "scan_id": event.get("scan_id"),
            "scan_timestamp": event.get("scan_timestamp"),
            "data": json.dumps(event.get("data", {})),
            "producer_host": meta.get("producer_host", ""),
            "producer_version": meta.get("producer_version", ""),
        }
        self._buffer.append(row)
        self._pending_ids.append(msg_id)

    async def _flush(self):
        """Insert buffered rows into ClickHouse with retry."""
        if not self._buffer:
            return

        for attempt in range(self.max_retries):
            try:
                await self.ch.insert_json_each_row("events", self._buffer)
                await self.consumer.ack(self._pending_ids)
                count = len(self._buffer)
                self._buffer.clear()
                self._pending_ids.clear()
                self._flushes += 1
                logger.info(f"Flushed {count} events to ClickHouse")
                return
            except Exception as exc:
                self._errors += 1
                logger.error(
                    f"ClickHouse insert attempt {attempt + 1}/{self.max_retries} failed: {exc}"
                )
                if attempt < self.max_retries - 1:
                    wait = 2 ** attempt
                    logger.info(f"Retrying in {wait}s...")
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "Max retries exceeded. Leaving messages in PEL for redelivery."
                    )
                    # Clear local buffer to prevent unbounded memory growth.
                    # Messages remain in Redis PEL and will be reclaimed.
                    self._buffer.clear()
                    self._pending_ids.clear()

    async def stop(self):
        self._running = False
        self.consumer.stop()

    @property
    def stats(self) -> dict:
        return {
            "flushes": self._flushes,
            "errors": self._errors,
            "buffered": len(self._buffer),
        }
