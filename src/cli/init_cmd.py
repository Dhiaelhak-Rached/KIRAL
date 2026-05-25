"""`kiral init` — Initialize ClickHouse schema with visual feedback."""

from __future__ import annotations

import asyncio

from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

from src.cli.banner import make_banner, make_status_badge
from src.cli.theme import PALETTE, console
from src.init_schema import init_schema


def init_cmd(user: str, password: str) -> None:
    """Initialize the ClickHouse database and events table."""
    console.print(make_banner())
    console.print()

    steps = [
        ("Connecting to ClickHouse", 0.5),
        ("Creating database asm_pipeline", 0.5),
        ("Creating table events", 0.8),
        ("Verifying schema", 0.3),
    ]

    with Live(console=console, refresh_per_second=10, transient=True) as live:
        for label, delay in steps:
            spinner = Spinner("dots", text=f" [kiral.primary]{label}[/]", style=PALETTE["primary"])
            live.update(spinner)
            asyncio.get_event_loop().run_until_complete(asyncio.sleep(delay))

    try:
        asyncio.run(init_schema(user=user, password=password))
        console.print()
        console.print(make_status_badge("completed"))
        console.print(Text("Schema initialized successfully.", style=f"bold {PALETTE['success']}"))
        console.print()
        console.print(
            Panel(
                Text.assemble(
                    Text("Next steps:\n", style=f"bold {PALETTE['bright']}"),
                    Text("1. Start the consumer: ", style=PALETTE["muted"]),
                    Text("docker run -d --name asm-consumer ...\n", style=PALETTE["primary"]),
                    Text("2. Run your first scan: ", style=PALETTE["muted"]),
                    Text("kiral scan <domain>", style=PALETTE["primary"]),
                ),
                border_style=PALETTE["success"],
                padding=(1, 2),
            )
        )
    except Exception as exc:
        console.print()
        console.print(make_status_badge("failed"))
        console.print(Text(f"Schema initialization failed: {exc}", style=f"bold {PALETTE['error']}"))
        raise SystemExit(1)
