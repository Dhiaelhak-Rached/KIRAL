"""Scanner execution layer.

Runs reconnaissance tools as asyncio subprocesses on the laptop.
Handles timeouts, output streaming, and resource protection.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AsyncIterator

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    """ClickHouse-compatible timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


@dataclass(frozen=True)
class RawFinding:
    """A single line of output from a reconnaissance tool."""

    tool: str
    target: str
    raw_line: str
    timestamp: str


class ToolRunner:
    """Executes scanner subprocesses with strict timeouts and stdout limits."""

    def __init__(self, timeout_sec: int = 600, max_stdout_mb: int = 512):
        self.timeout_sec = timeout_sec
        self.max_stdout_bytes = max_stdout_mb * 1024 * 1024

    async def run(
        self,
        cmd: list[str],
        target: str,
        timeout_sec: int | None = None,
    ) -> AsyncIterator[RawFinding]:
        """Run a tool and yield RawFinding objects line-by-line."""
        effective_timeout = timeout_sec if timeout_sec is not None else self.timeout_sec
        timestamp = _utc_now()
        tool_name = cmd[0]
        logger.info(f"[{tool_name}] starting for target={target}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,
            )
        except FileNotFoundError as exc:
            logger.error(f"[{tool_name}] not found in PATH")
            raise RuntimeError(f"Tool not installed: {tool_name}") from exc

        bytes_read = 0
        line_count = 0

        try:
            while True:
                try:
                    line = await asyncio.wait_for(
                        proc.stdout.readline(),
                        timeout=effective_timeout,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    raise RuntimeError(
                        f"[{tool_name}] timed out after {effective_timeout}s"
                    )

                if not line:
                    break

                bytes_read += len(line)
                if bytes_read > self.max_stdout_bytes:
                    proc.kill()
                    await proc.wait()
                    raise RuntimeError(
                        f"[{tool_name}] stdout exceeded {self.max_stdout_bytes} bytes"
                    )

                line_count += 1
                yield RawFinding(
                    tool=tool_name,
                    target=target,
                    raw_line=line.decode("utf-8", errors="replace").rstrip(),
                    timestamp=timestamp,
                )

            await proc.wait()

            stderr_data = await proc.stderr.read()
            if stderr_data:
                stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
                if proc.returncode != 0:
                    logger.warning(
                        f"[{tool_name}] exit={proc.returncode} stderr={stderr_text[:500]}"
                    )
                else:
                    logger.debug(f"[{tool_name}] stderr={stderr_text[:500]}")

            if proc.returncode == 0:
                logger.info(f"[{tool_name}] completed lines={line_count}")
            else:
                logger.warning(
                    f"[{tool_name}] completed with errors lines={line_count}"
                )

        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()


class Scanner:
    """High-level wrappers for each reconnaissance tool."""

    def __init__(self, runner: ToolRunner | None = None):
        self.runner = runner or ToolRunner()

    # ------------------------------------------------------------------ #
    # Stage 1: Subdomain enumeration
    # ------------------------------------------------------------------ #
    async def subfinder(self, domain: str) -> AsyncIterator[RawFinding]:
        cmd = ["subfinder", "-d", domain, "-all", "-silent", "-o", "-"]
        async for finding in self.runner.run(cmd, domain):
            if finding.raw_line:
                yield finding

    async def amass(self, domain: str) -> AsyncIterator[RawFinding]:
        cmd = ["amass", "enum", "-d", domain, "-passive", "-silent", "-o", "-"]
        async for finding in self.runner.run(cmd, domain, timeout_sec=600):
            if finding.raw_line:
                yield finding

    # ------------------------------------------------------------------ #
    # Stage 2: DNS resolution
    # ------------------------------------------------------------------ #
    async def dnsx(
        self, subdomains: list[str], target: str
    ) -> AsyncIterator[RawFinding]:
        if not subdomains:
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(subdomains))
            input_file = f.name

        try:
            cmd = [
                "dnsx",
                "-l", input_file,
                "-a", "-aaaa", "-cname",
                "-resp",
                "-json",
                "-o", "-",
            ]
            async for finding in self.runner.run(cmd, target, timeout_sec=120):
                if finding.raw_line:
                    yield finding
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # Stage 3: Port scanning
    # ------------------------------------------------------------------ #
    async def naabu(self, hosts: list[str], target: str) -> AsyncIterator[RawFinding]:
        if not hosts:
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(hosts))
            input_file = f.name

        try:
            cmd = [
                "naabu",
                "-list", input_file,
                "-top-ports", "1000",
                "-silent",
                "-json",
                "-o", "-",
                "-rate", "1000",
            ]
            async for finding in self.runner.run(cmd, target, timeout_sec=300):
                if finding.raw_line:
                    yield finding
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # Stage 4: HTTP probing
    # ------------------------------------------------------------------ #
    async def httpx(self, urls: list[str], target: str) -> AsyncIterator[RawFinding]:
        if not urls:
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(urls))
            input_file = f.name

        try:
            cmd = [
                "httpx",
                "-l", input_file,
                "-silent",
                "-json",
                "-o", "-",
                "-tech-detect",
                "-title",
                "-status-code",
                "-threads", "50",
            ]
            async for finding in self.runner.run(cmd, target, timeout_sec=180):
                if finding.raw_line:
                    yield finding
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass
