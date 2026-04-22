"""Abstract base class for all recon tool runners."""

from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class RunnerResult:
    """Normalised result returned by every tool runner."""

    tool_name: str
    command_run: str
    raw_output: str
    parsed_output: dict
    exit_code: int
    duration_ms: int
    error: str | None = None
    metadata: dict = field(default_factory=dict)


class BaseRunner(ABC):
    """Abstract base providing subprocess execution for all tool runners."""

    name: str = ""
    binary: str = ""
    default_timeout: int = 300

    @abstractmethod
    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the full argv list to pass to subprocess for this tool."""
        raise NotImplementedError("TODO: implement")

    @abstractmethod
    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse raw tool stdout into a structured dict."""
        raise NotImplementedError("TODO: implement")

    async def run(self, target: str, flags: dict | None = None) -> RunnerResult:
        """Execute the tool against target and return a normalised RunnerResult."""
        raise NotImplementedError("TODO: implement")

    async def get_version(self) -> str:
        """Run the tool's --version flag and return the version string."""
        raise NotImplementedError("TODO: implement")

    def is_available(self) -> bool:
        """Return True if the tool binary exists on PATH."""
        return shutil.which(self.binary) is not None
