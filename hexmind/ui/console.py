"""Rich console singleton and convenience print helpers for HexMind."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

from hexmind.constants import (
    COLOR_CYAN,
    COLOR_DIM,
    COLOR_GREEN,
    COLOR_ORANGE,
    COLOR_PURPLE,
    COLOR_RED,
    COLOR_SLATE,
    COLOR_SOFT_GREEN,
    COLOR_WHITE,
    COLOR_YELLOW,
)

_THEME = Theme({
    "hm.success": f"bold {COLOR_GREEN}",
    "hm.info": COLOR_CYAN,
    "hm.warning": COLOR_ORANGE,
    "hm.error": f"bold {COLOR_RED}",
    "hm.dim": COLOR_SLATE,
    "hm.critical": f"bold {COLOR_RED}",
    "hm.high": COLOR_ORANGE,
    "hm.medium": COLOR_YELLOW,
    "hm.low": COLOR_SOFT_GREEN,
    "hm.ai": COLOR_PURPLE,
    "hm.cmd": f"dim {COLOR_CYAN}",
    "hm.title": f"bold {COLOR_WHITE}",
})

# Module-level singleton — import this everywhere
console: Console = Console(theme=_THEME, highlight=False)


def print_success(msg: str) -> None:
    console.print(f"[hm.success]✓[/] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[hm.info]ℹ[/] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[hm.warning]⚠[/] {msg}")


def print_error(msg: str) -> None:
    console.print(f"[hm.error]✗[/] {msg}")


def print_dim(msg: str) -> None:
    console.print(f"[hm.dim]{msg}[/]")


def print_cmd(cmd: str) -> None:
    """Print a shell command in muted style (shown when show_commands=True)."""
    console.print(f"[hm.cmd]  $ {cmd}[/]")


def print_ai(msg: str) -> None:
    """Print AI-related status in purple."""
    console.print(f"[hm.ai]⚡[/] {msg}")


def rule(title: str = "", style: str = "steel_blue") -> None:
    """Print a styled horizontal rule."""
    console.rule(title, style=style)
