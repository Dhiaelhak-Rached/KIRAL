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

from src.config import settings

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

    @staticmethod
    async def _validate_tool_binary(tool_name: str):
        """Ensure we are calling the correct binary (not a shadowed Python package)."""
        if tool_name != "httpx":
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                tool_name,
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            text = stdout.decode("utf-8", errors="replace")
            text += stderr.decode("utf-8", errors="replace")
        except Exception:
            # If -version fails entirely, it's almost certainly the wrong httpx
            raise RuntimeError(
                "Wrong 'httpx' binary detected. The Python 'httpx' library "
                "(from your venv) is shadowing ProjectDiscovery's Go tool.\n"
                "Fix: prepend your Go bin directory to PATH before running:\n"
                '    $env:PATH = "C:\\Users\\rache\\go\\bin;$env:PATH"'
            )

        # PD httpx always prints a banner containing "projectdiscovery".
        # Python httpx (or any other impostor) never does.
        if "projectdiscovery" not in text.lower():
            raise RuntimeError(
                "Wrong 'httpx' binary detected. The Python 'httpx' library "
                "(from your venv) is shadowing ProjectDiscovery's Go tool.\n"
                "Fix: prepend your Go bin directory to PATH before running:\n"
                '    $env:PATH = "C:\\Users\\rache\\go\\bin;$env:PATH"'
            )

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
        await self._validate_tool_binary(tool_name)
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
    # NOTE: naabu is preserved but commented out. RustScan is the active
    # scanner. To restore naabu, uncomment the block below and comment
    # out the rustscan() method.
    # ------------------------------------------------------------------ #
    async def naabu(self, hosts: list[str], target: str) -> AsyncIterator[RawFinding]:
        """DEPRECATED — preserved for easy restoration. Use rustscan() instead."""
        # Original implementation commented out below. Uncomment to restore.
        # ------------------------------------------------------------------
        # if not hosts:
        #     return
        #
        # with tempfile.NamedTemporaryFile(
        #     mode="w", suffix=".txt", delete=False
        # ) as f:
        #     f.write("\n".join(hosts))
        #     input_file = f.name
        #
        # try:
        #     cmd = [
        #         "naabu",
        #         "-list", input_file,
        #         "-top-ports", "1000",
        #         "-silent",
        #         "-json",
        #         "-o", "-",
        #         "-rate", "1000",
        #     ]
        #     async for finding in self.runner.run(cmd, target, timeout_sec=300):
        #         if finding.raw_line:
        #             yield finding
        # finally:
        #     try:
        #         os.unlink(input_file)
        #     except OSError:
        #         pass
        return
        # ------------------------------------------------------------------

    async def rustscan(
        self, hosts: list[str], target: str
    ) -> AsyncIterator[RawFinding]:
        """Run RustScan for port discovery.

        Profile-aware: stealth (top-1000, low concurrency) for home networks,
        aggressive (full range, high concurrency) for server infrastructure.
        Output is greppable text; JSON is not supported.
        """
        if not hosts:
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(hosts))
            input_file = f.name

        try:
            if settings.scan_profile == "aggressive":
                cmd = [
                    "rustscan",
                    "-a", input_file,
                    "--range", "1-65535",
                    "-g",
                    "--ulimit", "5000",
                ]
                logger.info(
                    f"[{target}] rustscan aggressive profile: "
                    f"full range 1-65535, ulimit=5000"
                )
            else:
                cmd = [
                    "rustscan",
                    "-a", input_file,
                    "--top",
                    "-g",
                    "--ulimit", "500",
                    "-t", "1500",
                    "-b", "500",
                ]
                logger.info(
                    f"[{target}] rustscan stealth profile: "
                    f"top-1000 ports, ulimit=500, batch=500"
                )
            async for finding in self.runner.run(cmd, target, timeout_sec=300):
                if finding.raw_line:
                    yield finding
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # Stage 4: URL Discovery
    # ------------------------------------------------------------------ #
    async def gau(self, target: str) -> AsyncIterator[RawFinding]:
        """Run GetAllUrls to discover historical URLs from Wayback, CommonCrawl, OTX.

        Uses --subs to fetch URLs for the target domain and all subdomains.
        Output is one URL per line (plain text).
        """
        cmd = [
            "gau",
            "--subs",
            "--o", "-",
            target,
        ]
        async for finding in self.runner.run(cmd, target, timeout_sec=180):
            if finding.raw_line:
                yield finding

    async def katana(self, urls: list[str], target: str) -> AsyncIterator[RawFinding]:
        """Run Katana headless crawler to discover JS endpoints and API paths.

        Takes a list of seed URLs (subdomains) and crawls them.
        Output is JSON Lines (-json) with discovered endpoints.
        """
        if not urls:
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(urls))
            input_file = f.name

        try:
            cmd = [
                "katana",
                "-list", input_file,
                "-silent",
                "-json",
                "-o", "-",
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
    # Stage 5: Vulnerability detection
    # ------------------------------------------------------------------ #
    async def nuclei(self, urls: list[str], target: str) -> AsyncIterator[RawFinding]:
        """Run Nuclei vulnerability scanner against discovered service URLs.

        Output is JSON Lines (-jsonl), one vulnerability per line.
        Severity is filtered to low/medium/high/critical to skip info noise.
        """
        if not urls:
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\n".join(urls))
            input_file = f.name

        try:
            cmd = [
                "nuclei",
                "-l", input_file,
                "-jsonl",
                "-o", "-",
                "-silent",
                "-severity", "low,medium,high,critical",
            ]
            async for finding in self.runner.run(cmd, target, timeout_sec=600):
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
