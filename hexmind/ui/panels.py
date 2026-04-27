"""Styled Rich panels, tables, and live scan display components."""

from __future__ import annotations

import re as _re

from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hexmind.constants import (
    COLOR_CYAN,
    COLOR_DIM,
    COLOR_GREEN,
    COLOR_ORANGE,
    COLOR_RED,
    COLOR_SLATE,
    COLOR_SOFT_GREEN,
    COLOR_WHITE,
    COLOR_YELLOW,
    SEVERITY_COLORS,
)
from hexmind.ui.console import console

def _clean_title_for_display(title: str) -> str:
    """Strip trailing (CVE-XXXX-XXXXX) parentheticals from a finding title."""
    return _re.sub(
        r'\s*\(CVE-[\d-]+(?:,\s*CVE-[\d-]+)*\)\s*$',
        '', title, flags=_re.IGNORECASE,
    ).strip()


_PROFILE_COLORS: dict[str, str] = {
    "deep":     COLOR_RED,
    "standard": COLOR_CYAN,
    "quick":    COLOR_SOFT_GREEN,
    "stealth":  COLOR_ORANGE,
}
_STATUS_COLORS: dict[str, str] = {
    "done":    COLOR_GREEN,
    "running": COLOR_CYAN,
    "failed":  COLOR_RED,
    "pending": COLOR_SLATE,
}
_STATUS_ICONS: dict[str, str] = {
    "running": f"[{COLOR_CYAN}]⠋[/]",
    "done":    f"[{COLOR_GREEN}]✓[/]",
    "failed":  f"[{COLOR_RED}]✗[/]",
    "waiting": f"[{COLOR_SLATE}]○[/]",
    "skipped": f"[{COLOR_SLATE}]—[/]",
}


def render_findings_table(findings: list) -> Table:
    """Render a Rich Table of FindingData objects sorted by severity then confidence.

    Columns: #, Severity (colored chip), Category, Finding, CVE, Confidence
    """
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.severity_rank(), -f.confidence_score),
    )

    table = Table(
        box=box.ROUNDED,
        border_style="steel_blue",
        show_header=True,
        header_style=f"bold {COLOR_CYAN}",
        expand=True,
    )
    table.add_column("#",          width=4,       justify="right")
    table.add_column("Severity",   width=12)
    table.add_column("Category",   width=16)
    table.add_column("Finding",    min_width=30)
    table.add_column("CVE",        width=18)
    table.add_column("Confidence", width=12)

    for i, f in enumerate(sorted_findings, 1):
        sev   = f.severity.lower()
        color = SEVERITY_COLORS.get(sev, COLOR_SLATE)
        sev_cell = Text(f"● {sev.upper()}", style=f"bold {color}")

        cves = ", ".join(f.cve_ids[:2]) if f.cve_ids else "—"
        if len(f.cve_ids) > 2:
            cves += "…"

        pct = int(f.confidence_score * 100)
        if pct >= 80:
            conf_cell = Text(f"{pct}%", style=f"bold {COLOR_GREEN}")
        elif pct >= 50:
            conf_cell = Text(f"{pct}%", style=COLOR_YELLOW)
        else:
            conf_cell = Text(f"{pct}%", style=COLOR_SLATE)

        table.add_row(
            str(i),
            sev_cell,
            f.category or "—",
            _clean_title_for_display(f.title),
            cves,
            conf_cell,
        )

    return table


def render_scan_history_table(scans: list) -> Table:
    """Render a Rich Table of ScanSummary objects for the history command."""
    table = Table(
        box=box.ROUNDED,
        border_style="steel_blue",
        header_style=f"bold {COLOR_CYAN}",
        expand=True,
    )
    table.add_column("#ID",      width=7,       style=f"bold {COLOR_GREEN}")
    table.add_column("Target",   min_width=22,  style=COLOR_WHITE)
    table.add_column("Profile",  width=10)
    table.add_column("Status",   width=10)
    table.add_column("Risk",     width=6)
    table.add_column("Findings", width=22)
    table.add_column("Duration", width=10)
    table.add_column("Date",     width=12)

    for s in scans:
        pc     = _PROFILE_COLORS.get(s.profile, COLOR_SLATE)
        sc     = _STATUS_COLORS.get(s.status,  COLOR_SLATE)
        counts = s.finding_counts
        risk   = s.risk_score

        if risk is None:
            risk_str = "—"
        elif risk >= 70:
            risk_str = f"[bold {COLOR_RED}]{risk}[/]"
        elif risk >= 40:
            risk_str = f"[{COLOR_ORANGE}]{risk}[/]"
        else:
            risk_str = f"[{COLOR_SOFT_GREEN}]{risk}[/]"

        findings_str = (
            f"[{COLOR_RED}]{counts.get('critical', 0)}C[/] "
            f"[{COLOR_ORANGE}]{counts.get('high', 0)}H[/] "
            f"[{COLOR_YELLOW}]{counts.get('medium', 0)}M[/] "
            f"[{COLOR_SOFT_GREEN}]{counts.get('low', 0)}L[/] "
            f"[{COLOR_SLATE}]{counts.get('info', 0)}I[/]"
        )
        date_str = s.started_at.strftime("%Y-%m-%d") if s.started_at else "—"

        table.add_row(
            f"#{s.scan_id:04d}",
            s.target,
            f"[{pc}]{s.profile.upper()}[/]",
            f"[{sc}]{s.status.upper()}[/]",
            risk_str,
            findings_str,
            s.duration_str,
            date_str,
        )

    return table


def render_phase_header(
    phase_num: int, phase_name: str, status: str
) -> Panel:
    """Build a Rich Panel announcing the start or completion of a scan phase."""
    status_styles: dict[str, str] = {
        "RUNNING": f"bold {COLOR_CYAN}",
        "DONE":    f"bold {COLOR_GREEN}",
        "FAILED":  f"bold {COLOR_RED}",
    }
    style = status_styles.get(status.upper(), COLOR_SLATE)
    title = Text()
    title.append(f"Phase {phase_num} — ", style=f"dim {COLOR_CYAN}")
    title.append(phase_name, style=f"bold {COLOR_WHITE}")
    if status:
        title.append(f"  {status}", style=style)
    return Panel(title, border_style="steel_blue", padding=(0, 1))


def render_scan_complete_box(
    scan_id:     int,
    duration:    str,
    findings:    dict,        # {"critical": 1, "high": 3, ...}
    risk_score:  int | None,
    report_path: str = "",
) -> Panel:
    """Build the final summary Panel shown at end of scan."""
    risk_label = ""
    risk_color = COLOR_SLATE
    if risk_score is not None:
        from hexmind.constants import get_risk_label
        risk_label = get_risk_label(risk_score)
        _risk_colors = {
            "CRITICAL": COLOR_RED,
            "HIGH":     COLOR_ORANGE,
            "MEDIUM":   COLOR_YELLOW,
            "LOW":      COLOR_SOFT_GREEN,
            "MINIMAL":  COLOR_SLATE,
        }
        risk_color = _risk_colors.get(risk_label, COLOR_SLATE)

    lines: list[Text] = [
        Text.assemble(
            ("SCAN COMPLETE", f"bold {COLOR_GREEN}"),
            (f" · #{scan_id:04d}", COLOR_SLATE),
        ),
        Text.assemble(("Duration:   ", COLOR_SLATE), (duration, COLOR_WHITE)),
        Text.assemble(
            ("Findings:   ", COLOR_SLATE),
            (f"{findings.get('critical', 0)}C ", f"bold {COLOR_RED}"),
            (f"{findings.get('high',     0)}H ", COLOR_ORANGE),
            (f"{findings.get('medium',   0)}M ", COLOR_YELLOW),
            (f"{findings.get('low',      0)}L ", COLOR_SOFT_GREEN),
            (f"{findings.get('info',     0)}I",  COLOR_SLATE),
        ),
    ]
    if risk_score is not None:
        lines.append(Text.assemble(
            ("Risk Score: ", COLOR_SLATE),
            (f"{risk_score}/100 {risk_label}", f"bold {risk_color}"),
        ))
    if report_path:
        lines.append(Text.assemble(
            ("Report:     ", COLOR_SLATE),
            (report_path, COLOR_CYAN),
        ))

    content = Text("\n").join(lines)
    return Panel(content, border_style=COLOR_GREEN, padding=(1, 2))


def render_tool_row(
    tool_name: str, status: str, duration: str, summary: str
) -> Table:
    """Return a Rich renderable representing one tool row in the scan display."""
    grid = Table.grid(padding=(0, 1))
    grid.add_column("icon",    width=3)
    grid.add_column("name",    width=14, style=f"bold {COLOR_WHITE}")
    grid.add_column("elapsed", width=8,  style=COLOR_SLATE)
    grid.add_column("info",    style=COLOR_SLATE)
    icon = _STATUS_ICONS.get(status, "?")
    grid.add_row(icon, tool_name, duration, summary[:60])
    return grid


class LiveScanDisplay:
    """Context manager rendering an updating Rich Live layout during a scan."""

    def __init__(self, tool_names: list[str]) -> None:
        self._tools: dict[str, dict] = {
            n: {"status": "waiting", "info": "", "elapsed": ""}
            for n in tool_names
        }
        self._phase = ""
        self._live  = Live(
            self._render(),
            console=console,
            refresh_per_second=4,
            transient=False,
        )

    def __enter__(self) -> LiveScanDisplay:
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._live.update(self._render())
        self._live.__exit__(*args)

    def update_tool(
        self,
        tool_name: str,
        status:    str,
        info:      str = "",
        elapsed:   str = "",
    ) -> None:
        """Update the status row for tool_name and refresh the display."""
        if tool_name in self._tools:
            self._tools[tool_name] = {
                "status":  status,
                "info":    info,
                "elapsed": elapsed,
            }
            self._live.update(self._render())

    def set_phase(self, phase: str) -> None:
        """Update the current phase label and refresh the display."""
        self._phase = phase
        self._live.update(self._render())

    def _render(self) -> Table:
        table = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 1),
            expand=False,
        )
        table.add_column("icon",    width=3)
        table.add_column("name",    width=14, style=f"bold {COLOR_WHITE}")
        table.add_column("elapsed", width=8,  style=COLOR_SLATE)
        table.add_column("info",    style=COLOR_SLATE)

        for name, state in self._tools.items():
            icon = _STATUS_ICONS.get(state["status"], "?")
            table.add_row(
                icon,
                name,
                state["elapsed"],
                state["info"][:60],
            )
        return table
