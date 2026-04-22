"""Themed animated spinner context manager for individual tool runs."""

from __future__ import annotations

from hexmind.ui.console import console
from hexmind.constants import SPINNER_FRAMES


class LiveToolSpinner:
    """Displays an animated spinner in the terminal while a tool is running."""

    def __init__(self, tool_name: str) -> None:
        """Initialize the spinner with the tool name to display."""
        self.tool_name = tool_name
        self._live = None

    def __enter__(self) -> "LiveToolSpinner":
        """Start the spinner animation and return self."""
        raise NotImplementedError("TODO: implement")

    def __exit__(self, *args: object) -> None:
        """Stop the spinner and clear the line."""
        raise NotImplementedError("TODO: implement")

    def update(self, info: str) -> None:
        """Update the spinner status text without stopping it."""
        raise NotImplementedError("TODO: implement")
