"""ASCII art banner and phase separator display for HexMind CLI."""

from __future__ import annotations

from hexmind.ui.console import console

HEXMIND_ASCII: str = """\
  ██╗  ██╗███████╗██╗  ██╗███╗   ███╗██╗███╗   ██╗██████╗
  ██║  ██║██╔════╝╚██╗██╔╝████╗ ████║██║████╗  ██║██╔══██╗
  ███████║█████╗   ╚███╔╝ ██╔████╔██║██║██╔██╗ ██║██║  ██║
  ██╔══██║██╔══╝   ██╔██╗ ██║╚██╔╝██║██║██║╚██╗██║██║  ██║
  ██║  ██║███████╗██╔╝ ██╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝"""


def print_banner(
    target: str | None = None,
    scan_id: int | None = None,
    profile: str | None = None,
) -> None:
    """Print the HexMind ASCII art banner with optional scan metadata."""
    raise NotImplementedError("TODO: implement")


def print_phase_separator(phase_name: str, status: str = "") -> None:
    """Print a styled phase separator line with box-drawing characters."""
    raise NotImplementedError("TODO: implement")
