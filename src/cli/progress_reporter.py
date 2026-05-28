"""Live scan dashboard — bridges orchestrator events to Rich visuals."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
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

STAGE_NAMES = [
    "Subdomain Enumeration",
    "DNS Resolution",
    "Port Scanning",
    "URL Discovery",
    "HTTP Probing",
    "Vulnerability Detection",
]

STAGE_TOOLS = ["subfinder", "dnsx", "rustscan", "gau+katana", "httpx", "nuclei"]


@dataclass
class StageState:
    status: str = "waiting"  # waiting | active | completed | failed
    count: int = 0
    name: str = ""
    tool: str = ""


class ScanReporter:
    """Manages the live Rich display during a scan."""

    def __init__(self) -> None:
        self.stages: list[StageState] = [
            StageState(name=STAGE_NAMES[i], tool=STAGE_TOOLS[i])
            for i in range(len(STAGE_NAMES))
        ]
        self.published_total: int = 0
        self.start_time: float | None = None
        self.target: str = ""
        self.scan_id: str = ""
        self.profile: str = ""
        self._live: Live | None = None
        self._progress = Progress(
            SpinnerColumn("dots", style=STYLES["primary"]),
            TextColumn("[kiral.primary]{task.fields[name]}", justify="left"),
            BarColumn(
                bar_width=None,
                style=PALETTE["muted"],
                complete_style=PALETTE["success"],
                finished_style=PALETTE["success"],
            ),
            TextColumn("[kiral.bright]{task.percentage:>3.0f}%"),
            TextColumn("[kiral.muted]│"),
            TextColumn("[kiral.accent]{task.fields[count]:,}[/] [kiral.muted]found"),
            TextColumn("[kiral.muted]│"),
            TextColumn("{task.fields[status_icon]}"),
            console=console,
            expand=True,
        )
        self._tasks: list = []

    # --------------------------------------------------------------------- #
    # Lifecycle
    # --------------------------------------------------------------------- #
    def start(self, target: str, scan_id: str, profile: str) -> None:
        self.target = target
        self.scan_id = scan_id
        self.profile = profile
        self.start_time = time.time()
        for i, st in enumerate(self.stages):
            t = self._progress.add_task(
                "",
                name=f"Stage {i + 1}/{len(self.stages)}: {st.name}",
                count=0,
                status_icon=self._icon(st.status),
                total=100,
                completed=0,
            )
            self._tasks.append(t)
        self._live = Live(self._render(), console=console, refresh_per_second=8)
        self._live.start()

    def stop(self) -> None:
        if self._live:
            self._live.stop()
            self._live = None

    # --------------------------------------------------------------------- #
    # State updates
    # --------------------------------------------------------------------- #
    def set_stage_active(self, stage_idx: int) -> None:
        """stage_idx is 0-based."""
        for i in range(4):
            if i < stage_idx:
                self.stages[i].status = "completed"
                self._progress.update(
                    self._tasks[i],
                    completed=100,
                    status_icon=self._icon("completed"),
                )
            elif i == stage_idx:
                self.stages[i].status = "active"
                self._progress.update(
                    self._tasks[i],
                    status_icon=self._icon("active"),
                )
            else:
                self.stages[i].status = "waiting"
                self._progress.update(
                    self._tasks[i],
                    completed=0,
                    status_icon=self._icon("waiting"),
                )
        self._refresh()

    def set_stage_done(self, stage_idx: int, count: int | None = None) -> None:
        st = self.stages[stage_idx]
        st.status = "completed"
        if count is not None:
            st.count = count
        self._progress.update(
            self._tasks[stage_idx],
            completed=100,
            count=st.count,
            status_icon=self._icon("completed"),
        )
        self._refresh()

    def set_stage_failed(self, stage_idx: int) -> None:
        self.stages[stage_idx].status = "failed"
        self._progress.update(
            self._tasks[stage_idx],
            status_icon=self._icon("failed"),
        )
        self._refresh()

    def update_count(self, stage_idx: int, count: int) -> None:
        self.stages[stage_idx].count = count
        # For active stages, animate bar to 50% (unknown real progress)
        completed = 50 if self.stages[stage_idx].status == "active" else 100
        self._progress.update(
            self._tasks[stage_idx],
            count=count,
            completed=completed,
            status_icon=self._icon(self.stages[stage_idx].status),
        )
        self._refresh()

    def update_published(self, total: int) -> None:
        self.published_total = total
        self._refresh()

    # --------------------------------------------------------------------- #
    # Rendering
    # --------------------------------------------------------------------- #
    def _icon(self, status: str) -> str:
        icons = {
            "waiting": "[kiral.waiting]⏸ waiting[/]",
            "active": "[kiral.spinner]▶ running[/]",
            "completed": "[kiral.done]✓ done[/]",
            "failed": "[kiral.error]✗ failed[/]",
        }
        return icons.get(status, status)

    def _render(self) -> Panel:
        # Header
        header_text = Text.assemble(
            Text("Target: ", style=f"bold {PALETTE['muted']}"),
            Text(self.target, style=f"bold {PALETTE['bright']}"),
            Text("  │  ", style=PALETTE["muted"]),
            Text("Profile: ", style=f"bold {PALETTE['muted']}"),
            Text(
                self.profile.upper(),
                style=f"bold {PALETTE['warning'] if self.profile == 'stealth' else PALETTE['error']}",
            ),
            Text("  │  ", style=PALETTE["muted"]),
            Text("Scan ID: ", style=f"bold {PALETTE['muted']}"),
            Text(self.scan_id[:8], style=f"italic {PALETTE['accent']}"),
        )

        # Footer HUD
        elapsed = time.time() - (self.start_time or time.time())
        eps = self.published_total / elapsed if elapsed > 0 else 0
        hud = Text.assemble(
            Text("Published: ", style=PALETTE["muted"]),
            Text(f"{self.published_total:,}", style=f"bold {PALETTE['primary']}"),
            Text("  │  ", style=PALETTE["muted"]),
            Text("Events/sec: ", style=PALETTE["muted"]),
            Text(f"{eps:.0f}", style=f"bold {PALETTE['accent']}"),
            Text("  │  ", style=PALETTE["muted"]),
            Text("Elapsed: ", style=PALETTE["muted"]),
            Text(
                f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}",
                style=f"bold {PALETTE['warning']}",
            ),
        )

        # Combine into a Group so mixed renderables work
        body = Group(
            header_text,
            Text(""),
            self._progress.get_renderable(),
            Text(""),
            hud,
        )

        return Panel(
            body,
            title="[kiral.primary]KIRAL Reconnaissance Pipeline",
            border_style=PALETTE["primary"],
            padding=(1, 2),
        )

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())
