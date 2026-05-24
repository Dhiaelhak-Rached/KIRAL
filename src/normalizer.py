"""Event normalization and deduplication layer.

Converts raw scanner output into strict canonical events.
Filters duplicates using a Redis-backed probabilistic cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Optional, Union

import redis.asyncio as redis

from src.config import settings
from src.scanner import RawFinding

logger = logging.getLogger(__name__)


def dedup_key(event: dict) -> str:
    """Generate deterministic SHA256 key for an event.

    The key captures the semantic identity of the finding so that
    re-running the same scan against the same target does not produce
    duplicate events.
    """
    event_type = event["event_type"]
    data = event.get("data", {})

    if event_type == "SUBDOMAIN_FOUND":
        raw = f"sub:{event['asset']}"
    elif event_type == "DNS_RESOLVED":
        vals = ",".join(sorted(data.get("resolved_values", [])))
        raw = f"dns:{data.get('hostname', '')}:{data.get('record_type', '')}:{vals}"
    elif event_type == "PORT_FOUND":
        raw = (
            f"port:{data.get('ip', '')}:"
            f"{data.get('port', 0)}:{data.get('protocol', 'tcp')}"
        )
    elif event_type == "SERVICE_DETECTED":
        raw = f"svc:{event['asset']}:{data.get('status_code', 0)}"
    else:
        raw = json.dumps(event, sort_keys=True)

    return hashlib.sha256(raw.encode()).hexdigest()


class EventNormalizer:
    """Transforms RawFinding objects into canonical event dictionaries."""

    def __init__(self, scan_id: str, producer_host: str):
        self.scan_id = scan_id
        self.producer_host = producer_host
        self.base_meta = {
            "producer_host": producer_host,
            "producer_version": "0.1.0",
        }

    def normalize(
        self, raw: RawFinding
    ) -> Optional[Union[dict, list[dict]]]:
        """Parse a RawFinding into one or more canonical events."""
        parsers = {
            "subfinder": self._parse_subfinder,
            "amass": self._parse_amass,
            "dnsx": self._parse_dnsx,
            # "naabu": self._parse_naabu,  # replaced by rustscan
            "rustscan": self._parse_rustscan,
            "httpx": self._parse_httpx,
        }
        parser = parsers.get(raw.tool)
        if not parser:
            logger.warning(f"No parser registered for tool={raw.tool}")
            return None
        try:
            return parser(raw)
        except Exception as exc:
            logger.error(
                f"Parser {raw.tool} failed: {exc} on line={raw.raw_line[:200]}"
            )
            return None

    def _base_event(self, raw: RawFinding, event_type: str, asset: str) -> dict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "target": raw.target,
            "asset": asset,
            "source_tool": raw.tool,
            "scan_id": self.scan_id,
            "scan_timestamp": raw.timestamp,
            "metadata": self.base_meta.copy(),
        }

    def _parse_subfinder(self, raw: RawFinding) -> Optional[dict]:
        subdomain = raw.raw_line.strip()
        if not subdomain or "." not in subdomain:
            return None
        event = self._base_event(raw, "SUBDOMAIN_FOUND", subdomain)
        event["data"] = {
            "subdomain": subdomain,
            "source": "passive",
            "is_wildcard": subdomain.startswith("*."),
        }
        return event

    def _parse_amass(self, raw: RawFinding) -> Optional[dict]:
        # Passive amass output is identical to subfinder: one subdomain per line
        return self._parse_subfinder(raw)

    def _parse_dnsx(self, raw: RawFinding) -> list[dict]:
        try:
            j = json.loads(raw.raw_line)
        except json.JSONDecodeError:
            return []

        host = j.get("host", "")
        if not host:
            return []

        events = []
        for rtype in ("a", "aaaa", "cname"):
            values = j.get(rtype)
            if values:
                ev = self._base_event(raw, "DNS_RESOLVED", host)
                ev["data"] = {
                    "hostname": host,
                    "record_type": rtype.upper(),
                    "resolved_values": values
                    if isinstance(values, list)
                    else [values],
                    "resolver_used": j.get("resolver", ""),
                    "response_time_ms": j.get("response_time_ms", 0) or 0,
                }
                events.append(ev)
        return events

    # NOTE: naabu parser preserved but commented out. rustscan replaces it.
    # def _parse_naabu(self, raw: RawFinding) -> Optional[dict]:
    #     try:
    #         j = json.loads(raw.raw_line)
    #     except json.JSONDecodeError:
    #         return None
    #
    #     ip = j.get("ip", j.get("host", ""))
    #     port = j.get("port", 0)
    #     if not ip or not port:
    #         return None
    #
    #     event = self._base_event(raw, "PORT_FOUND", f"{ip}:{port}")
    #     event["data"] = {
    #         "ip": ip,
    #         "port": port,
    #         "protocol": j.get("protocol", "tcp"),
    #         "scan_type": j.get("scan_type", "connect"),
    #     }
    #     return event

    def _parse_rustscan(self, raw: RawFinding) -> list[dict]:
        """Parse RustScan greppable output into PORT_FOUND events.

        Greppable format: 192.168.1.1 -> [80, 443, 8080]
        Returns one event per open port.
        """
        line = raw.raw_line.strip()
        if not line or " -> [" not in line:
            return []

        # Split IP from port list
        ip_part, ports_part = line.split(" -> [", 1)
        ip = ip_part.strip()

        # Remove trailing bracket and split ports
        ports_str = ports_part.rstrip("]")
        if not ports_str:
            return []

        ports = [p.strip() for p in ports_str.split(",")]

        events = []
        for p in ports:
            try:
                port_num = int(p)
            except ValueError:
                continue

            event = self._base_event(raw, "PORT_FOUND", f"{ip}:{port_num}")
            event["data"] = {
                "ip": ip,
                "port": port_num,
                "protocol": "tcp",
                "scan_type": "syn",
            }
            events.append(event)

        return events

    def _parse_httpx(self, raw: RawFinding) -> Optional[dict]:
        try:
            j = json.loads(raw.raw_line)
        except json.JSONDecodeError:
            return None

        url = j.get("url", "")
        host = j.get("host", "")
        ip = j.get("ip", "")
        port = j.get("port", 0)
        asset = url or f"{host}:{port}"
        if not asset:
            return None

        event = self._base_event(raw, "SERVICE_DETECTED", asset)
        event["data"] = {
            "url": url,
            "host": host,
            "ip": ip,
            "port": port,
            "scheme": j.get("scheme", "https"),
            "status_code": j.get("status_code", 0) or 0,
            "title": j.get("title", ""),
            "technologies": j.get("tech", []) or [],
            "headers": {
                k.lower(): v for k, v in (j.get("headers") or {}).items()
            },
            "tls_version": j.get("tls_version", ""),
            "response_hash_sha256": j.get("body_sha256", ""),
        }
        return event


class Deduplicator:
    """Redis-backed duplicate filter with TTL."""

    def __init__(
        self,
        redis_client: redis.Redis,
        ttl_sec: int = 86400 * 7,
    ):
        self.r = redis_client
        self.ttl = ttl_sec
        self.set_key = "asm:dedup:seen"

    async def is_duplicate(self, event: dict) -> bool:
        """Return True if the event has been seen before.

        On Redis failure, fails OPEN (allows duplicates) to avoid
        blocking the pipeline.
        """
        try:
            key = dedup_key(event)
            added = await self.r.sadd(self.set_key, key)
            if added:
                await self.r.expire(self.set_key, self.ttl)
                return False
            return True
        except redis.RedisError as exc:
            logger.warning(f"Dedup Redis error (failing open): {exc}")
            return False
