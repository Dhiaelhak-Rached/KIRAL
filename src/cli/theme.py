"""KIRAL visual design system — colors, styles, and console."""

from __future__ import annotations

from rich.console import Console
from rich.style import Style
from rich.theme import Theme

# --------------------------------------------------------------------------- #
# Cyberpunk / Dark Intelligence Palette
# --------------------------------------------------------------------------- #
PALETTE = {
    "primary": "#00f0ff",      # Neon cyan — headers, active states
    "success": "#00ff41",      # Matrix green — completed, healthy
    "warning": "#ff9f1c",      # Cyber amber — stealth, idle, caution
    "error": "#ff0044",        # Alert red — failures, critical
    "accent": "#bd00ff",       # Plasma purple — scan IDs, badges
    "muted": "#8a8f98",        # Steel gray — secondary text
    "bright": "#ffffff",       # Pure white — emphasis
    "dark": "#0a0a0f",         # Deep black — implicit bg
}

# --------------------------------------------------------------------------- #
# Rich Theme definition (maps style names to color rules)
# --------------------------------------------------------------------------- #
KIRAL_THEME = Theme(
    {
        "kiral.primary": f"bold {PALETTE['primary']}",
        "kiral.success": f"bold {PALETTE['success']}",
        "kiral.warning": f"bold {PALETTE['warning']}",
        "kiral.error": f"bold {PALETTE['error']}",
        "kiral.accent": f"bold {PALETTE['accent']}",
        "kiral.muted": PALETTE["muted"],
        "kiral.bright": f"bold {PALETTE['bright']}",
        "kiral.border": PALETTE["primary"],
        "kiral.title": f"bold {PALETTE['primary']}",
        "kiral.label": f"bold {PALETTE['muted']}",
        "kiral.value": PALETTE["bright"],
        "kiral.spinner": f"bold {PALETTE['primary']}",
        "kiral.done": f"bold {PALETTE['success']}",
        "kiral.waiting": PALETTE["muted"],
        "kiral.scan_id": f"italic {PALETTE['accent']}",
    }
)

# --------------------------------------------------------------------------- #
# Global console instance (used across the CLI)
# --------------------------------------------------------------------------- #
console = Console(theme=KIRAL_THEME, highlight=False)

# --------------------------------------------------------------------------- #
# Pre-built styles for programmatic use
# --------------------------------------------------------------------------- #
STYLES = {
    "primary": Style(color=PALETTE["primary"], bold=True),
    "success": Style(color=PALETTE["success"], bold=True),
    "warning": Style(color=PALETTE["warning"], bold=True),
    "error": Style(color=PALETTE["error"], bold=True),
    "accent": Style(color=PALETTE["accent"], bold=True),
    "muted": Style(color=PALETTE["muted"]),
    "bright": Style(color=PALETTE["bright"], bold=True),
    "border": Style(color=PALETTE["primary"]),
}


def hex_color(name: str) -> str:
    """Return hex value for a palette color by name."""
    return PALETTE.get(name, "#ffffff")
