"""`kiral status` — System health check."""

from __future__ import annotations

import asyncio
import shutil
import subprocess

import redis.asyncio as redis
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import make_banner, make_status_badge
from src.cli.theme import PALETTE, console
from src.config import settings


async def _check_redis() -> tuple[str, str]:
    try:
        r = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            socket_connect_timeout=5,
        )
        await r.ping()
        info = await r.info("server")
        version = info.get("redis_version", "?")
        await r.aclose()
        return "connected", f"{settings.redis_host}:{settings.redis_port}  v{version}"
    except Exception as exc:
        return "disconnected", str(exc)


async def _check_clickhouse() -> tuple[str, str]:
    try:
        import httpx
        auth = (settings.ch_user, settings.ch_password) if settings.ch_password else None
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                settings.ch_url,
                params={"database": settings.ch_database},
                content="SELECT 1",
                auth=auth,
            )
            resp.raise_for_status()
            resp2 = await client.post(
                settings.ch_url,
                params={"database": settings.ch_database},
                content="EXISTS TABLE events",
                auth=auth,
            )
            exists = resp2.text.strip()
            return "connected", f"{settings.ch_url} — {settings.ch_database}.events {'OK' if exists == '1' else 'MISSING'}"
    except Exception as exc:
        return "disconnected", str(exc)


def _check_tool(tool: str) -> tuple[str, str]:
    path = shutil.which(tool)
    if not path:
        return "error", "not in PATH"
    try:
        if tool == "httpx":
            result = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
            text = result.stdout + result.stderr
            if "projectdiscovery" not in text.lower():
                return "error", "wrong binary (Python httpx)"
            return "ok", path
        elif tool == "rustscan":
            subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
        elif tool == "amass":
            subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
        else:
            subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=5)
        return "ok", path
    except Exception as exc:
        return "error", str(exc)


def _check_consumer() -> tuple[str, str]:
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=asm-consumer", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "asm-consumer" in result.stdout:
            return "running", "asm-consumer (docker)"
        return "waiting", "not running"
    except FileNotFoundError:
        return "waiting", "docker not available"
    except Exception as exc:
        return "error", str(exc)


def status_cmd() -> None:
    """Check health of all KIRAL components."""
    console.print(make_banner())
    console.print()

    redis_status, redis_detail = asyncio.run(_check_redis())
    ch_status, ch_detail = asyncio.run(_check_clickhouse())

    table = Table(show_header=False, box=box.ROUNDED, border_style=PALETTE["primary"], padding=(0, 1))
    table.add_column("Service", style=f"bold {PALETTE['primary']}")
    table.add_column("Status")
    table.add_column("Detail", style=PALETTE["muted"])

    table.add_row("Redis", make_status_badge(redis_status), redis_detail)
    table.add_row("ClickHouse", make_status_badge(ch_status), ch_detail)

    for tool in ("subfinder", "dnsx", "rustscan", "httpx", "nuclei"):
        tstatus, tdetail = _check_tool(tool)
        table.add_row(tool, make_status_badge(tstatus), tdetail)

    cons_status, cons_detail = _check_consumer()
    table.add_row("Consumer", make_status_badge(cons_status), cons_detail)

    panel = Panel(
        table,
        title="[kiral.primary]System Status",
        border_style=PALETTE["primary"],
        padding=(1, 2),
    )
    console.print(panel)
