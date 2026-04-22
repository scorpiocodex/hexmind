"""Styled Rich panels, tables, and live scan display components."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from hexmind.ui.console import console


def render_tool_row(
    tool_name: str, status: str, duration: str, summary: str
) -> object:
    """Return a Rich renderable representing one tool row in the scan display."""
    raise NotImplementedError("TODO: implement")


def render_findings_table(findings: list) -> Table:
    """Build and return a Rich Table of findings sorted by severity."""
    raise NotImplementedError("TODO: implement")


def render_scan_history_table(scans: list) -> Table:
    """Build and return a Rich Table of scan history records."""
    raise NotImplementedError("TODO: implement")


def render_phase_header(
    phase_num: int, phase_name: str, status: str
) -> Panel:
    """Build and return a Rich Panel announcing the start of a scan phase."""
    raise NotImplementedError("TODO: implement")


class LiveScanDisplay:
    """Context manager that renders an updating Rich Live layout during a scan."""

    def __enter__(self) -> "LiveScanDisplay":
        """Start the live display and return self."""
        raise NotImplementedError("TODO: implement")

    def __exit__(self, *args: object) -> None:
        """Stop and clean up the live display."""
        raise NotImplementedError("TODO: implement")

    def update_tool(self, tool_name: str, status: str, info: str = "") -> None:
        """Update the status row for tool_name in the live display."""
        raise NotImplementedError("TODO: implement")

    def set_phase(self, phase: str) -> None:
        """Update the current phase label in the live display."""
        raise NotImplementedError("TODO: implement")
