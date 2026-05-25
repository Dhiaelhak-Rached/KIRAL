"""Reusable Rich components for the KIRAL CLI."""

from __future__ import annotations

from rich.align import Align
from rich.columns import Columns
from rich.panel import Panel
from rich import box
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from src.cli.theme import PALETTE, STYLES, console


def stage_progress() -> Progress:
    """Return a Rich Progress bar configured for pipeline stages."""
    return Progress(
        SpinnerColumn("dots", style=STYLES["primary"]),
        TextColumn("[kiral.primary]{task.fields[stage_name]}", justify="left"),
        BarColumn(bar_width=30, style=PALETTE["muted"], complete_style=PALETTE["success"]),
        TextColumn("[kiral.bright]{task.percentage:>3.0f}%"),
        TextColumn("[kiral.muted]│"),
        TextColumn("[kiral.accent]{task.fields[count]:,}[/] [kiral.muted]found"),
        TextColumn("[kiral.muted]│"),
        TextColumn("{task.fields[status_msg]}"),
        console=console,
        expand=True,
    )


def make_counter_panel(label: str, value: int, color: str = PALETTE["primary"]) -> Panel:
    """A HUD-style counter box."""
    inner = Text.assemble(
        Text(f"{value:,}\n", style=f"bold {color}"),
        Text(label, style=PALETTE["muted"]),
    )
    return Panel(
        Align.center(inner),
        border_style=color,
        padding=(1, 2),
    )


def make_hud_grid(
    total_published: int,
    events_per_sec: float,
    elapsed_sec: float,
) -> Table:
    """Return a compact HUD table for the scan footer."""
    grid = Table.grid(expand=True)
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")

    grid.add_row(
        make_counter_panel("PUBLISHED", total_published, PALETTE["primary"]),
        make_counter_panel("EVENTS/SEC", int(events_per_sec), PALETTE["accent"]),
        make_counter_panel("ELAPSED", f"{int(elapsed_sec // 60):02d}:{int(elapsed_sec % 60):02d}", PALETTE["warning"]),
    )
    return grid


def make_config_table(target: str, profile: str, scan_id: str, redis_host: str, ch_host: str) -> Table:
    """Show scan configuration as a clean table."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style=f"bold {PALETTE['muted']}", justify="right")
    table.add_column(style=PALETTE["bright"])

    profile_color = PALETTE["warning"] if profile == "stealth" else PALETTE["error"]
    profile_text = Text(profile.upper(), style=f"bold {profile_color}")

    table.add_row("Target", target)
    table.add_row("Profile", profile_text)
    table.add_row("Scan ID", Text(scan_id, style=f"italic {PALETTE['accent']}"))
    table.add_row("Redis", redis_host)
    table.add_row("ClickHouse", ch_host)
    return table


def make_summary_table(event_counts: dict[str, int]) -> Table:
    """Render event-type counts as a rich table."""
    table = Table(title="[kiral.primary]Scan Summary", box=box.ROUNDED, border_style=PALETTE["primary"])
    table.add_column("Event Type", style=f"bold {PALETTE['primary']}")
    table.add_column("Count", justify="right", style=PALETTE["bright"])
    for etype, count in sorted(event_counts.items()):
        table.add_row(etype, f"{count:,}")
    return table


def make_findings_table(title: str, rows: list[dict], columns: list[str]) -> Table:
    """Generic rich table for query/export output."""
    table = Table(title=f"[kiral.primary]{title}", box=box.ROUNDED, border_style=PALETTE["primary"])
    for col in columns:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[str(row.get(c, "")) for c in columns])
    return table
