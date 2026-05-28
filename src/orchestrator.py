"""Main pipeline orchestrator.

Coordinates the six-stage reconnaissance pipeline:
1. Subdomain enumeration   (subfinder + amass)
2. DNS resolution          (dnsx)
3. Port scanning           (rustscan)  # naabu preserved but replaced
4. URL Discovery           (gau + katana)
5. HTTP probing            (httpx)
6. Vulnerability detection (nuclei)

Normalized events are deduplicated and published to Redis Streams.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import uuid
from datetime import datetime, timezone

import redis.asyncio as redis

from src.config import settings
from src.normalizer import Deduplicator, EventNormalizer
from src.producer import RedisEventProducer
from src.safety import SafetyLimiter, validate_target
from src.scanner import RawFinding, Scanner

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """End-to-end scan orchestrator running on the laptop."""

    def __init__(self, target: str, scan_id: str | None = None):
        self.target = target
        self.scan_id = scan_id or str(uuid.uuid4())
        self.shutdown_event = asyncio.Event()
        self._setup_signals()

        # Redis client (shared for producer + dedup)
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            socket_connect_timeout=10,
            socket_keepalive=True,
            health_check_interval=30,
        )

        # Pipeline components
        self.producer = RedisEventProducer(
            self.redis_client,
            max_stream_len=settings.max_stream_len,
        )
        self.dedup = Deduplicator(self.redis_client)
        self.normalizer = EventNormalizer(
            scan_id=self.scan_id,
            producer_host=settings.producer_host,
        )
        self.scanner = Scanner()
        self.safety = SafetyLimiter(settings.max_events_per_scan)

        # Accumulators for downstream stages
        self.subdomains: set[str] = set()
        self.ips: set[str] = set()
        self.urls: list[str] = []
        self.services: set[str] = set()

    def _setup_signals(self):
        """Register graceful shutdown handlers where supported."""
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, self._handle_shutdown)
        except (NotImplementedError, RuntimeError):
            # Windows or no running loop
            pass

    def _handle_shutdown(self):
        logger.info("Shutdown signal received, finishing current stage...")
        self.shutdown_event.set()

    async def _process_findings(
        self, findings: asyncio.AsyncIterator[RawFinding]
    ) -> int:
        """Normalize, deduplicate, and publish a stream of findings.

        Returns the number of unique events published.
        """
        published = 0
        async for raw in findings:
            if self.shutdown_event.is_set():
                logger.info("Shutdown detected, breaking finding stream")
                break

            self.safety.check()

            try:
                normalized = self.normalizer.normalize(raw)
            except Exception as exc:
                logger.error(f"Normalization error: {exc}")
                continue

            if normalized is None:
                continue

            events = normalized if isinstance(normalized, list) else [normalized]
            for event in events:
                try:
                    is_dup = await self.dedup.is_duplicate(event)
                    if is_dup:
                        continue

                    await self.producer.publish(event)
                    published += 1
                    self._extract_downstream_data(event)
                except Exception as exc:
                    logger.error(f"Event pipeline error: {exc}")
                    continue

        return published

    def _extract_downstream_data(self, event: dict):
        """Accumulate data needed for subsequent pipeline stages."""
        event_type = event["event_type"]
        data = event.get("data", {})

        if event_type == "SUBDOMAIN_FOUND":
            self.subdomains.add(data["subdomain"])

        elif event_type == "DNS_RESOLVED":
            if data.get("record_type") == "A":
                self.ips.update(data.get("resolved_values", []))

        elif event_type == "PORT_FOUND":
            ip = data.get("ip", "")
            port = data.get("port", 0)
            # Build candidate URLs for httpx
            if port == 443:
                self.urls.append(f"https://{ip}")
            elif port == 80:
                self.urls.append(f"http://{ip}")
            else:
                self.urls.append(f"http://{ip}:{port}")
                self.urls.append(f"https://{ip}:{port}")

        elif event_type == "SERVICE_DETECTED":
            url = data.get("url", "")
            if url:
                self.services.add(url)

        elif event_type == "URL_DISCOVERED":
            url = data.get("url", "")
            if url:
                self.urls.append(url)

    async def run(self):
        """Execute the six-stage pipeline."""
        logger.info(f"Scan {self.scan_id} starting for target={self.target}")
        start_time = datetime.now(timezone.utc)

        try:
            # ------------------------------------------------------------------
            # Stage 1: Subdomain enumeration (concurrent)
            # ------------------------------------------------------------------
            logger.info("Stage 1/6: Subdomain enumeration")
            stage1_tools = {
                "subfinder": self.scanner.subfinder(self.target),
            }
            tasks = {
                name: asyncio.create_task(self._process_findings(it))
                for name, it in stage1_tools.items()
            }
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            summary = []
            for (name, _), res in zip(tasks.items(), results):
                if isinstance(res, Exception):
                    logger.error(f"[{name}] failed: {res}")
                    summary.append(f"{name}=FAILED")
                else:
                    summary.append(f"{name}={res}")
            logger.info(
                f"Stage 1 complete: {' '.join(summary)} "
                f"unique_subdomains={len(self.subdomains)}"
            )

            if self.shutdown_event.is_set():
                return

            # ------------------------------------------------------------------
            # Stage 2: DNS resolution
            # ------------------------------------------------------------------
            if self.subdomains:
                logger.info(
                    f"Stage 2/6: DNS resolution for {len(self.subdomains)} subdomains"
                )
                dns_count = await self._process_findings(
                    self.scanner.dnsx(list(self.subdomains), self.target)
                )
                logger.info(
                    f"Stage 2 complete: dns_records={dns_count} unique_ips={len(self.ips)}"
                )

            if self.shutdown_event.is_set():
                return

            # ------------------------------------------------------------------
            # Stage 3: Port scanning
            # ------------------------------------------------------------------
            if self.ips:
                logger.info(
                    f"Stage 3/6: Port scanning for {len(self.ips)} IPs"
                )
                port_count = await self._process_findings(
                    self.scanner.rustscan(list(self.ips), self.target)
                )
                logger.info(f"Stage 3 complete: ports_found={port_count}")

            if self.shutdown_event.is_set():
                return

            # ------------------------------------------------------------------
            # Stage 4: URL Discovery (gau + katana)
            # ------------------------------------------------------------------
            if self.subdomains:
                logger.info(
                    f"Stage 4/6: URL Discovery for {len(self.subdomains)} subdomains"
                )
                url_tools = {
                    "gau": self.scanner.gau(self.target),
                    "katana": self.scanner.katana(list(self.subdomains), self.target),
                }
                tasks = {
                    name: asyncio.create_task(self._process_findings(it))
                    for name, it in url_tools.items()
                }
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for (name, _), res in zip(tasks.items(), results):
                    if isinstance(res, Exception):
                        logger.error(f"[{name}] failed: {res}")
                logger.info(
                    f"Stage 4 complete: urls_discovered={len(self.urls)}"
                )

            if self.shutdown_event.is_set():
                return

            # ------------------------------------------------------------------
            # Stage 5: HTTP probing
            # ------------------------------------------------------------------
            for sub in self.subdomains:
                self.urls.extend(
                    [
                        f"https://{sub}",
                        f"http://{sub}",
                        f"https://{sub}:8443",
                        f"http://{sub}:8080",
                    ]
                )

            seen = set()
            deduped_urls = []
            for url in self.urls:
                if url not in seen:
                    seen.add(url)
                    deduped_urls.append(url)
            self.urls = deduped_urls

            if self.urls:
                logger.info(
                    f"Stage 5/6: HTTP probing for {len(self.urls)} URLs"
                )
                chunk_size = 5_000
                total_http = 0
                for i in range(0, len(self.urls), chunk_size):
                    if self.shutdown_event.is_set():
                        break
                    chunk = self.urls[i : i + chunk_size]
                    chunk_count = await self._process_findings(
                        self.scanner.httpx(chunk, self.target)
                    )
                    total_http += chunk_count
                    logger.debug(
                        f"httpx chunk {i // chunk_size + 1}: {chunk_count} events"
                    )
                logger.info(
                    f"Stage 5 complete: services_detected={total_http}"
                )

            if self.shutdown_event.is_set():
                return

            # ------------------------------------------------------------------
            # Stage 6: Vulnerability detection (nuclei)
            # ------------------------------------------------------------------
            service_urls = sorted({u for u in self.services if u})
            if service_urls:
                logger.info(
                    f"Stage 6/6: Vulnerability detection for {len(service_urls)} URLs"
                )
                vuln_count = await self._process_findings(
                    self.scanner.nuclei(service_urls, self.target)
                )
                logger.info(
                    f"Stage 6 complete: vulnerabilities_found={vuln_count}"
                )
            else:
                logger.info("Stage 6/6: Skipped (no services to scan)")

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(
                f"Scan {self.scan_id} finished in {elapsed:.1f}s. "
                f"Total published={self.producer.published_count}"
            )

        except Exception as exc:
            logger.exception(f"Scan failed: {exc}")
            raise
        finally:
            await self.redis_client.aclose()


async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.orchestrator <target_domain>")
        sys.exit(1)

    target = sys.argv[1].strip().lower()
    if not validate_target(target):
        logger.error(f"Invalid or unauthorized target: {target}")
        sys.exit(1)

    orchestrator = PipelineOrchestrator(target)
    try:
        await orchestrator.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        orchestrator._handle_shutdown()


if __name__ == "__main__":
    asyncio.run(main())
