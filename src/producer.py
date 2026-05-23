"""Redis Streams producer.

Publishes canonical events to the remote Redis Stream from the laptop.
"""

from __future__ import annotations

import json
import logging

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class RedisEventProducer:
    """Async producer for Redis Streams with approximate maxlen trimming."""

    def __init__(
        self,
        redis_client: redis.Redis,
        stream_key: str = "asm:events:v1",
        max_stream_len: int = 1_000_000,
    ):
        self.r = redis_client
        self.stream_key = stream_key
        self.max_stream_len = max_stream_len
        self._published = 0

    async def publish(self, event: dict) -> str:
        """Publish a single event and return the stream message ID."""
        payload = json.dumps(event, separators=(",", ":"), default=str)
        msg_id = await self.r.xadd(
            self.stream_key,
            {"payload": payload},
            maxlen=self.max_stream_len,
            approximate=True,
        )
        decoded = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
        self._published += 1
        return decoded

    async def publish_batch(self, events: list[dict]) -> list[str]:
        """Publish multiple events via a pipeline."""
        if not events:
            return []

        pipe = self.r.pipeline()
        for event in events:
            payload = json.dumps(event, separators=(",", ":"), default=str)
            pipe.xadd(
                self.stream_key,
                {"payload": payload},
                maxlen=self.max_stream_len,
                approximate=True,
            )
        results = await pipe.execute()
        decoded = [
            r.decode() if isinstance(r, bytes) else r for r in results
        ]
        self._published += len(decoded)
        return decoded

    @property
    def published_count(self) -> int:
        return self._published
