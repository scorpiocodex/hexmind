"""ASCII art banner and phase separator display for HexMind CLI."""

from __future__ import annotations

from rich.panel import Panel
from rich.text import Text

from hexmind.constants import (
    COLOR_CYAN,
    COLOR_DIM,
    COLOR_GREEN,
    COLOR_WHITE,
    HEXMIND_CODENAME,
    HEXMIND_VERSION,
)
from hexmind.ui.console import console

HEXMIND_ASCII: str = """\
  ██╗  ██╗███████╗██╗  ██╗███╗   ███╗██╗███╗   ██╗██████╗
  ██║  ██║██╔════╝╚██╗██╔╝████╗ ████║██║████╗  ██║██╔══██╗
  ███████║█████╗   ╚███╔╝ ██╔████╔██║██║██╔██╗ ██║██║  ██║
  ██╔══██║██╔══╝   ██╔██╗ ██║╚██╔╝██║██║██║╚██╗██║██║  ██║
  ██║  ██║███████╗██╔╝ ██╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝"""

SUBTITLE: str = "AI Penetration Testing Assistant · Fully Local · Zero Cloud"


def print_banner(
    target: str | None = None,
    scan_id: int | None = None,
    profile: str | None = None,
    model: str | None = None,
) -> None:
    """Print the HexMind ASCII art banner with optional scan metadata."""
    content = Text()
    content.append(HEXMIND_ASCII, style=f"bold {COLOR_GREEN}")
    content.append("\n")
    content.append(SUBTITLE, style=f"dim {COLOR_CYAN}")

    if any(x is not None for x in [target, scan_id, profile, model]):
        meta = Text("\n\n  ")
        first = True
        pairs: list[tuple[str, str, str]] = []
        if target:
            pairs.append(("Target  › ", target, COLOR_WHITE))
        if scan_id is not None:
            pairs.append(("Scan ID › ", f"#{scan_id:04d}", COLOR_CYAN))
        if profile:
            pairs.append(("Profile › ", profile.upper(), COLOR_GREEN))
        if model:
            pairs.append(("Model   › ", model, COLOR_CYAN))
        for label, value, style in pairs:
            if not first:
                meta.append("    ")
            meta.append(label, style="dim")
            meta.append(value, style=style)
            first = False
        content.append_text(meta)

    console.print(
        Panel(
            content,
            border_style="steel_blue",
            padding=(0, 2),
            subtitle=f"v{HEXMIND_VERSION} [{HEXMIND_CODENAME}]",
            subtitle_align="right",
        )
    )


def print_phase_separator(phase_name: str, status: str = "") -> None:
    """Print a styled phase divider line."""
    status_colors: dict[str, str] = {
        "RUNNING": COLOR_CYAN,
        "DONE": COLOR_GREEN,
        "FAILED": "bright_red",
        "": COLOR_DIM,
    }
    color = status_colors.get(status.upper(), COLOR_DIM)
    label = f"[ {phase_name} ]"
    if status:
        label += f" [{color}]{status}[/{color}]"
    console.rule(label, style="steel_blue")
