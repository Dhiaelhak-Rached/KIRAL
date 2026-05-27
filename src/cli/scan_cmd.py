"""`kiral scan` — Run reconnaissance with live dashboard."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import make_banner
from src.cli.progress_reporter import ScanReporter
from src.cli.theme import PALETTE, console
from src.cli.widgets import make_config_table
from src.config import settings
from src.normalizer import Deduplicator, EventNormalizer
from src.orchestrator import PipelineOrchestrator
from src.producer import RedisEventProducer
from src.safety import SafetyLimiter, validate_target
from src.scanner import RawFinding, Scanner


class RichOrchestrator(PipelineOrchestrator):
    """PipelineOrchestrator with Rich live-display hooks."""

    def __init__(self, target: str, reporter: ScanReporter, scan_id: str | None = None):
        self.target = target
        self.scan_id = scan_id or str(uuid.uuid4())
        self.shutdown_event = asyncio.Event()
        self._setup_signals()

        import redis.asyncio as redis
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            socket_connect_timeout=10,
            socket_keepalive=True,
            health_check_interval=30,
        )
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

        self.subdomains: set[str] = set()
        self.ips: set[str] = set()
        self.urls: list[str] = []
        self.services: set[str] = set()

        self.reporter = reporter
        self._stage_idx = 0
        self._poll_task: asyncio.Task | None = None

    async def _process_findings(
        self, findings: asyncio.AsyncIterator[RawFinding]
    ) -> int:
        async def _poll() -> None:
            while True:
                await asyncio.sleep(0.5)
                if not self.reporter:
                    continue
                count = 0
                if self._stage_idx == 0:
                    count = len(self.subdomains)
                elif self._stage_idx == 1:
                    count = len(self.ips)
                elif self._stage_idx == 2:
                    count = len(self.urls)
                elif self._stage_idx == 3:
                    count = len(self.urls)
                elif self._stage_idx == 4:
                    count = len(self.services)
                self.reporter.update_count(self._stage_idx, count)
                self.reporter.update_published(self.producer.published_count)

        self._poll_task = asyncio.create_task(_poll())
        try:
            published = await super()._process_findings(findings)
        finally:
            if self._poll_task:
                self._poll_task.cancel()
                try:
                    await self._poll_task
                except asyncio.CancelledError:
                    pass
        return published

    async def run(self) -> None:
        self.reporter.start(self.target, self.scan_id, settings.scan_profile)
        start_time = datetime.now(timezone.utc)

        try:
            # Stage 1
            self._stage_idx = 0
            self.reporter.set_stage_active(0)
            stage1_tools = {"subfinder": self.scanner.subfinder(self.target)}
            tasks = {
                name: asyncio.create_task(self._process_findings(it))
                for name, it in stage1_tools.items()
            }
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for (name, _), res in zip(tasks.items(), results):
                if isinstance(res, Exception):
                    console.print(f"[kiral.error][{name}] failed: {res}")
            self.reporter.set_stage_done(0, len(self.subdomains))

            if self.shutdown_event.is_set():
                return

            # Stage 2
            if self.subdomains:
                self._stage_idx = 1
                self.reporter.set_stage_active(1)
                await self._process_findings(
                    self.scanner.dnsx(list(self.subdomains), self.target)
                )
                self.reporter.set_stage_done(1, len(self.ips))

            if self.shutdown_event.is_set():
                return

            # Stage 3
            if self.ips:
                self._stage_idx = 2
                self.reporter.set_stage_active(2)
                await self._process_findings(
                    self.scanner.rustscan(list(self.ips), self.target)
                )
                self.reporter.set_stage_done(2, len(self.urls))

            if self.shutdown_event.is_set():
                return

            # Stage 4
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
            deduped = []
            for url in self.urls:
                if url not in seen:
                    seen.add(url)
                    deduped.append(url)
            self.urls = deduped

            if self.urls:
                self._stage_idx = 3
                self.reporter.set_stage_active(3)
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
                self.reporter.set_stage_done(3, total_http)

            if self.shutdown_event.is_set():
                return

            # Stage 5
            service_urls = sorted({u for u in self.services if u})
            if service_urls:
                self._stage_idx = 4
                self.reporter.set_stage_active(4)
                vuln_count = await self._process_findings(
                    self.scanner.nuclei(service_urls, self.target)
                )
                self.reporter.set_stage_done(4, vuln_count)

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.reporter.update_published(self.producer.published_count)

        except Exception as exc:
            console.print(f"[kiral.error]Scan failed: {exc}")
            raise
        finally:
            # Mark any remaining stages as completed so spinners stop
            for i in range(5):
                if self.reporter.stages[i].status != "completed":
                    self.reporter.set_stage_done(i, 0)
            self.reporter.stop()
            await self.redis_client.aclose()


def scan_cmd(domain: str, profile: Optional[str]) -> None:
    """Launch a full reconnaissance scan with live dashboard."""
    target = domain.strip().lower()
    if not validate_target(target):
        console.print(f"[kiral.error]Invalid or unauthorized target: {target}")
        raise SystemExit(1)

    if profile:
        settings.scan_profile = profile  # type: ignore[misc]

    console.print(make_banner())
    console.print()

    config_table = make_config_table(
        target=target,
        profile=settings.scan_profile,
        scan_id=str(uuid.uuid4()),
        redis_host=settings.redis_host,
        ch_host=settings.ch_url,
    )
    console.print(
        Panel(
            config_table,
            title="[kiral.primary]Mission Configuration",
            border_style=PALETTE["primary"],
            padding=(1, 2),
        )
    )
    console.print()

    reporter = ScanReporter()
    orchestrator = RichOrchestrator(target, reporter)
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        orchestrator._handle_shutdown()
        console.print("\n[kiral.warning]Shutdown signal received, finishing current stage...")

    console.print()
    _print_completion_report(orchestrator, reporter)


def _print_completion_report(orch: RichOrchestrator, reporter: ScanReporter) -> None:
    """Render the post-scan summary."""
    elapsed = 0.0
    if reporter.start_time:
        elapsed = time.time() - reporter.start_time

    summary_data = {
        "Subdomains": len(orch.subdomains),
        "Unique IPs": len(orch.ips),
        "Candidate URLs": len(orch.urls),
        "Vulnerabilities": reporter.stages[4].count if reporter.stages else 0,
        "Total Events": orch.producer.published_count,
    }

    table = Table(title="[kiral.primary]Scan Complete", box=box.ROUNDED, border_style=PALETTE["primary"])
    table.add_column("Metric", style=f"bold {PALETTE['primary']}")
    table.add_column("Value", justify="right", style=PALETTE["bright"])
    for k, v in summary_data.items():
        table.add_row(k, f"{v:,}")
    table.add_row("Duration", f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}")

    meta = Text.assemble(
        Text("Scan ID: ", style=PALETTE["muted"]),
        Text(orch.scan_id, style=f"italic {PALETTE['accent']}"),
        Text("  │  ", style=PALETTE["muted"]),
        Text("Profile: ", style=PALETTE["muted"]),
        Text(
            settings.scan_profile.upper(),
            style=f"bold {PALETTE['warning'] if settings.scan_profile == 'stealth' else PALETTE['error']}",
        ),
    )

    console.print(table)
    console.print()
    console.print(Panel(meta, border_style=PALETTE["accent"], padding=(0, 2)))
