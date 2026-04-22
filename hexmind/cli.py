"""Typer CLI entry point exposing all HexMind commands."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="hexmind",
    help="AI-powered local penetration testing assistant.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="IP address or domain to scan"),
    profile: str = typer.Option(
        "standard", "--profile", "-p",
        help="Scan profile: quick|standard|deep|stealth",
    ),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis phase"),
    allow_private: bool = typer.Option(
        False, "--allow-private", help="Allow scanning RFC-1918 private addresses"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Run a full reconnaissance and AI analysis scan against target."""
    raise NotImplementedError("TODO: implement")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Filter by target value"
    ),
) -> None:
    """List recent scan sessions with status and finding counts."""
    raise NotImplementedError("TODO: implement")


@app.command()
def show(
    scan_id: int = typer.Argument(..., help="Scan ID to display"),
) -> None:
    """Display full findings and AI summary for a specific scan."""
    raise NotImplementedError("TODO: implement")


@app.command()
def report(
    scan_id: int = typer.Argument(..., help="Scan ID to export"),
    format: str = typer.Option(
        "html", "--format", "-f", help="Output format: md|html|pdf|json"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Custom output file path"
    ),
) -> None:
    """Export a scan report in the specified format."""
    raise NotImplementedError("TODO: implement")


@app.command()
def targets() -> None:
    """List all previously scanned targets with last-seen timestamps."""
    raise NotImplementedError("TODO: implement")


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query string"),
) -> None:
    """Run a standalone DuckDuckGo or CVE search and display results."""
    raise NotImplementedError("TODO: implement")


@app.command()
def compare(
    scan_id_1: int = typer.Argument(..., help="First scan ID"),
    scan_id_2: int = typer.Argument(..., help="Second scan ID"),
) -> None:
    """Diff two scans of the same target and highlight new or resolved findings."""
    raise NotImplementedError("TODO: implement")


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Print current configuration"),
    set_: Optional[str] = typer.Option(
        None, "--set", help="Set a config key=value pair"
    ),
    reset: bool = typer.Option(False, "--reset", help="Reset config to defaults"),
) -> None:
    """Show or modify HexMind configuration settings."""
    raise NotImplementedError("TODO: implement")


@app.command()
def doctor() -> None:
    """Check that all required binaries and services are available."""
    # TODO: Display VERSION_ROADMAP and current version stage
    # TODO: Show "Next milestone: 0.2.0 — All runners + AI engine"
    raise NotImplementedError("TODO: implement")


if __name__ == "__main__":
    app()
