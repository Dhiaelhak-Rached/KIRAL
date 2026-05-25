"""ASCII art banners and cyber-styling helpers."""

from __future__ import annotations

from rich.align import Align
from rich.columns import Columns
from rich.panel import Panel
from rich.text import Text

from src.cli.theme import PALETTE, console

# --------------------------------------------------------------------------- #
# ASCII Art
# --------------------------------------------------------------------------- #
KIRAL_ASCII = r"""
██╗  ██╗██╗██████╗  █████╗ ██╗     
██║ ██╔╝██║██╔══██╗██╔══██╗██║     
█████╔╝ ██║██████╔╝███████║██║     
██╔═██╗ ██║██╔══██╗██╔══██║██║     
██║  ██╗██║██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
""".strip("\n")

KIRAL_TAGLINE = "Attack Surface Intelligence Terminal"

# Smaller compact banner for secondary screens
KIRAL_COMPACT = "[kiral.primary]KIRAL[/] [kiral.muted]—[/] [kiral.bright]Attack Surface Intelligence[/]"


def make_banner(compact: bool = False) -> Panel | Text:
    """Return a styled banner panel.

    Args:
        compact: If True, return a single-line text instead of the big ASCII.
    """
    if compact:
        return Text.from_markup(KIRAL_COMPACT)

    art_lines = KIRAL_ASCII.splitlines()
    # Colorize the ASCII art with a subtle gradient effect
    # Top lines get more cyan, bottom lines blend to purple
    styled_lines: list[Text] = []
    total = len(art_lines)
    for i, line in enumerate(art_lines):
        if i < total // 2:
            color = PALETTE["primary"]
        elif i < total * 3 // 4:
            color = "#4d8aff"  # blend cyan → purple
        else:
            color = PALETTE["accent"]
        styled_lines.append(Text(line, style=f"bold {color}"))

    art_text = Text("\n").join(styled_lines)
    tagline = Text(f"\n{KIRAL_TAGLINE}", style=f"italic {PALETTE['muted']}")
    content = Text.assemble(art_text, tagline)

    panel = Panel(
        Align.center(content),
        border_style=PALETTE["primary"],
        padding=(1, 2),
    )
    return panel


def make_header(title: str, subtitle: str | None = None) -> Panel:
    """Create a section header panel."""
    text = Text(title, style=f"bold {PALETTE['primary']}")
    if subtitle:
        text.append(f"\n{subtitle}", style=PALETTE["muted"])
    return Panel(
        Align.center(text),
        border_style=PALETTE["primary"],
        padding=(0, 2),
    )


def make_status_badge(status: str) -> Text:
    """Return a color-coded status badge."""
    status_map = {
        "connected": ("CONNECTED", PALETTE["success"]),
        "running": ("RUNNING", PALETTE["success"]),
        "ok": ("OK", PALETTE["success"]),
        "completed": ("COMPLETED", PALETTE["success"]),
        "waiting": ("WAITING", PALETTE["muted"]),
        "idle": ("IDLE", PALETTE["muted"]),
        "stealth": ("STEALTH", PALETTE["warning"]),
        "aggressive": ("AGGRESSIVE", PALETTE["error"]),
        "failed": ("FAILED", PALETTE["error"]),
        "error": ("ERROR", PALETTE["error"]),
        "disconnected": ("DISCONNECTED", PALETTE["error"]),
        "active": ("ACTIVE", PALETTE["primary"]),
    }
    label, color = status_map.get(status.lower(), (status.upper(), PALETTE["muted"]))
    return Text(f" {label} ", style=f"bold {color}")


def make_profile_badge(profile: str) -> Text:
    """Return a styled scan-profile badge."""
    return make_status_badge(profile)
