"""Context builder: assembles tool results and history into AI message lists."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hexmind.ai.engine import AIEngine


class ContextBuilder:
    """Formats tool outputs and conversation history into Ollama message payloads."""

    def __init__(self, target: str, profile: str, engine: "AIEngine") -> None:
        """Initialize with the scan target, profile, and AI engine for token estimation."""
        self.target = target
        self.profile = profile
        self.engine = engine

    def build_initial_context(
        self,
        tool_results: dict,
        iteration: int,
        max_iterations: int,
        previous_summary: str = "",
    ) -> list[dict]:
        """Build the initial Ollama messages list from baseline recon tool results."""
        raise NotImplementedError("TODO: implement")

    def build_followup_context(
        self,
        messages: list[dict],
        new_tool_results: dict,
        search_results: list[str],
        iteration: int,
    ) -> list[dict]:
        """Append new tool results and search text to an existing messages list."""
        raise NotImplementedError("TODO: implement")

    def summarize_previous_findings(self, findings: list) -> str:
        """Return a compact text summary of prior findings for context injection."""
        raise NotImplementedError("TODO: implement")
