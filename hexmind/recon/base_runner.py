"""Abstract base class for all recon tool runners."""

from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from hexmind.core.exceptions import ToolExecutionError, ToolNotFoundError, ToolTimeoutError


@dataclass
class RunnerResult:
    """Normalised result returned by every tool runner."""

    tool_name:     str
    command_run:   str
    raw_output:    str
    parsed_output: dict
    exit_code:     int
    duration_ms:   int
    error:         Optional[str]      = None
    metadata:      dict               = field(default_factory=dict)
    started_at:    Optional[datetime] = field(default_factory=datetime.utcnow)

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and self.error is None

    def to_tool_result_data(self):
        """Convert to ToolResultData for DB persistence."""
        from hexmind.db.schemas import ToolResultData
        return ToolResultData(
            tool_name=self.tool_name,
            command_run=self.command_run,
            raw_output=self.raw_output,
            parsed_output=self.parsed_output,
            exit_code=self.exit_code,
            duration_ms=self.duration_ms,
            error=self.error,
            metadata=self.metadata,
            started_at=self.started_at,
            tool_version=self.metadata.get("version", ""),
        )


class BaseRunner(ABC):
    """Abstract base providing subprocess execution for all tool runners."""

    name:            str = ""
    binary:          str = ""
    default_timeout: int = 300

    _version_cache: dict[str, str] = {}

    @abstractmethod
    def build_command(self, target: str, flags: dict) -> list[str]:
        """Return the full argv list to pass to subprocess for this tool."""

    @abstractmethod
    def parse_output(self, raw: str, exit_code: int) -> dict:
        """Parse raw tool stdout into a structured dict."""

    def is_available(self) -> bool:
        """Return True if the tool binary exists on PATH."""
        return shutil.which(self.binary) is not None

    async def get_version(self) -> str:
        """Run binary --version, cache and return the version string."""
        if self.binary in self._version_cache:
            return self._version_cache[self.binary]
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = (stdout or stderr or b"").decode("utf-8", errors="replace")
            version = output.strip().split("\n")[0][:80]
            self._version_cache[self.binary] = version
            return version
        except Exception:
            return "unknown"

    async def run(
        self,
        target:  str,
        flags:   dict = {},
        timeout: int | None = None,
    ) -> RunnerResult:
        """Execute the tool as a subprocess and return a RunnerResult.

        Never raises — all exceptions are captured in the error field.
        """
        if not self.is_available():
            return RunnerResult(
                tool_name=self.name,
                command_run=self.binary,
                raw_output="",
                parsed_output={},
                exit_code=-1,
                duration_ms=0,
                error=(
                    f"Binary '{self.binary}' not found on PATH. "
                    f"Install: sudo apt install {self.binary}"
                ),
            )

        cmd     = self.build_command(target, flags)
        cmd_str = " ".join(cmd)
        t_out   = timeout or self.default_timeout
        start   = time.monotonic()
        started = datetime.utcnow()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=t_out
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
                elapsed = int((time.monotonic() - start) * 1000)
                return RunnerResult(
                    tool_name=self.name,
                    command_run=cmd_str,
                    raw_output="",
                    parsed_output={},
                    exit_code=-1,
                    duration_ms=elapsed,
                    error=f"Tool timed out after {t_out}s",
                    started_at=started,
                )

            elapsed   = int((time.monotonic() - start) * 1000)
            raw       = (stdout or b"").decode("utf-8", errors="replace")
            raw_err   = (stderr or b"").decode("utf-8", errors="replace")
            combined  = raw if raw.strip() else raw_err
            exit_code = proc.returncode or 0

            if exit_code != 0 and not combined.strip():
                return RunnerResult(
                    tool_name=self.name,
                    command_run=cmd_str,
                    raw_output="",
                    parsed_output={},
                    exit_code=exit_code,
                    duration_ms=elapsed,
                    error=f"{self.name} returned exit code {exit_code} with no output",
                    started_at=started,
                )

            parsed    = {}
            parse_err = None
            try:
                parsed = self.parse_output(combined, exit_code)
            except Exception as e:
                parse_err = f"Parse error: {e}"

            version = await self.get_version()

            return RunnerResult(
                tool_name=self.name,
                command_run=cmd_str,
                raw_output=combined,
                parsed_output=parsed,
                exit_code=exit_code,
                duration_ms=elapsed,
                error=parse_err,
                metadata={"version": version, "stderr": raw_err[:500]},
                started_at=started,
            )

        except PermissionError:
            elapsed = int((time.monotonic() - start) * 1000)
            return RunnerResult(
                tool_name=self.name,
                command_run=cmd_str,
                raw_output="",
                parsed_output={},
                exit_code=1,
                duration_ms=elapsed,
                error=(
                    f"{self.name} requires elevated privileges — "
                    f"re-run with sudo or use a non-privileged scan flag (e.g. -sT for nmap)"
                ),
                started_at=started,
            )
        except FileNotFoundError:
            elapsed = int((time.monotonic() - start) * 1000)
            return RunnerResult(
                tool_name=self.name,
                command_run=cmd_str,
                raw_output="",
                parsed_output={},
                exit_code=-1,
                duration_ms=elapsed,
                error=(
                    f"Binary '{self.binary}' not found — "
                    f"install with: sudo apt install {self.binary}"
                ),
                started_at=started,
            )
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return RunnerResult(
                tool_name=self.name,
                command_run=cmd_str,
                raw_output="",
                parsed_output={},
                exit_code=-1,
                duration_ms=elapsed,
                error=f"Execution error: {e}",
                started_at=started,
            )
