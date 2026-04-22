"""Rich console singleton and convenience print helpers for HexMind."""

from rich.console import Console

console: Console = Console(highlight=False)


def print_info(msg: str) -> None:
    """Print an informational message in electric cyan."""
    console.print(f"[#00b4d8]{msg}[/#00b4d8]")


def print_success(msg: str) -> None:
    """Print a success message in matrix green."""
    console.print(f"[bold #00ff9f]{msg}[/bold #00ff9f]")


def print_error(msg: str) -> None:
    """Print an error message in alert red."""
    console.print(f"[bold #ff4444]{msg}[/bold #ff4444]")


def print_warning(msg: str) -> None:
    """Print a warning message in amber orange."""
    console.print(f"[bold #ff8c00]{msg}[/bold #ff8c00]")


def print_dim(msg: str) -> None:
    """Print a dimmed supplementary message in muted slate."""
    console.print(f"[dim #94a3b8]{msg}[/dim #94a3b8]")
