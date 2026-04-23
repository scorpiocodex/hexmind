"""Themed animated spinner context manager for individual tool runs."""

from __future__ import annotations

import time

from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from hexmind.constants import COLOR_CYAN, COLOR_GREEN, COLOR_RED
from hexmind.ui.console import console


class LiveToolSpinner:
    """Context manager: shows an animated spinner with elapsed time while a tool runs."""

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        self._start: float = time.monotonic()
        self._live: Live | None = None
        self._status: str = "running"
        self._info: str = ""

    def __enter__(self) -> "LiveToolSpinner":
        self._start = time.monotonic()
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=8,
            transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None and self._status == "running":
            self._status = "failed"
        if self._live is not None:
            self._live.update(self._render())
            self._live.__exit__(exc_type, exc_val, exc_tb)

    def update(self, info: str) -> None:
        """Update the status line text mid-run."""
        self._info = info
        if self._live is not None:
            self._live.update(self._render())

    def done(self, info: str = "") -> None:
        """Mark the tool run as complete."""
        self._status = "done"
        self._info = info
        if self._live is not None:
            self._live.update(self._render())

    def failed(self, info: str = "") -> None:
        """Mark the tool run as failed."""
        self._status = "failed"
        self._info = info
        if self._live is not None:
            self._live.update(self._render())

    def _elapsed(self) -> str:
        secs = time.monotonic() - self._start
        if secs < 60:
            return f"{secs:.1f}s"
        m, s = divmod(int(secs), 60)
        return f"{m}m {s}s"

    def _render(self) -> Table:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(width=2)
        grid.add_column(min_width=16)
        grid.add_column(width=10)
        grid.add_column()

        if self._status == "running":
            icon = Spinner("dots", style=COLOR_CYAN)
            name_style = f"bold {COLOR_CYAN}"
        elif self._status == "done":
            icon = Text("✓", style=f"bold {COLOR_GREEN}")
            name_style = f"bold {COLOR_GREEN}"
        else:
            icon = Text("✗", style=f"bold {COLOR_RED}")
            name_style = f"bold {COLOR_RED}"

        grid.add_row(
            icon,
            Text(f"{self.tool_name:<14}", style=name_style),
            Text(f"→ {self._elapsed()}", style="dim"),
            Text(self._info, style="bright_black"),
        )
        return grid
