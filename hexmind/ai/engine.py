"""Ollama API client wrapper providing generation, streaming, and health checks."""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator

import httpx


class AIEngine:
    """Wraps the Ollama HTTP API for chat generation and model management."""

    def __init__(self, base_url: str, model: str) -> None:
        """Initialize with the Ollama base URL and model name to use."""
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client: httpx.AsyncClient | None = None

    async def generate(self, prompt: str) -> str:
        """Send a single prompt and return the complete response string."""
        raise NotImplementedError("TODO: implement")

    async def generate_stream(
        self, messages: list[dict]
    ) -> AsyncGenerator[str, None]:
        """Yield response tokens one by one from the Ollama streaming endpoint."""
        raise NotImplementedError("TODO: implement")
        # Required to make this a generator at parse time
        yield ""  # pragma: no cover

    async def generate_full(self, messages: list[dict]) -> str:
        """Return the complete response by consuming generate_stream internally."""
        raise NotImplementedError("TODO: implement")

    async def check_available(self) -> tuple[bool, str]:
        """Return (is_available, message) after probing the Ollama /api/tags endpoint."""
        raise NotImplementedError("TODO: implement")

    async def pull_model_if_needed(self, model: str) -> bool:
        """Pull model from Ollama registry if not already present; return success."""
        raise NotImplementedError("TODO: implement")

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count using the ~4 chars-per-token heuristic."""
        raise NotImplementedError("TODO: implement")
