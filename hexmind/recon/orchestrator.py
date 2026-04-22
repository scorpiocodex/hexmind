"""Async recon pipeline coordinator: manages tiered tool execution."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from hexmind.recon.base_runner import RunnerResult

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from rich.console import Console


class ReconOrchestrator:
    """Runs recon tools in dependency-ordered async tiers and persists results."""

    def __init__(
        self,
        target: str,
        profile: str,
        db_session: "Session",
        scan_id: int,
        console: "Console",
    ) -> None:
        """Initialize the orchestrator with target, profile, and DB session."""
        self.target = target
        self.profile = profile
        self.db_session = db_session
        self.scan_id = scan_id
        self.console = console

    async def run_all(self, target: str, profile: str) -> dict[str, RunnerResult]:
        """Execute all tools for the given profile in tiered parallel batches."""
        raise NotImplementedError("TODO: implement")

    async def run_single(
        self, tool_name: str, custom_args: list[str] | None = None
    ) -> RunnerResult:
        """Run a single named tool with optional AI-specified custom arguments."""
        raise NotImplementedError("TODO: implement")

    def get_available_tools(self) -> list[str]:
        """Return names of all tools whose binaries are present on PATH."""
        raise NotImplementedError("TODO: implement")

    def _should_run_nikto(self, nmap_result: dict) -> bool:
        """Return True if nmap found open HTTP/HTTPS ports that warrant a Nikto scan."""
        raise NotImplementedError("TODO: implement")

    def _should_run_gobuster(self, nmap_result: dict) -> bool:
        """Return True if nmap found open web ports that warrant directory bruting."""
        raise NotImplementedError("TODO: implement")
