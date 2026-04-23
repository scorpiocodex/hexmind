"""Ollama API client wrapper providing generation, streaming, and health checks."""

from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from hexmind.core.exceptions import (
    AIError,
    ModelNotFoundError,
    OllamaNotRunningError,
    OllamaTimeoutError,
)


class OllamaEngine:
    """Async client for the Ollama local LLM API (/api/chat endpoint)."""

    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model    = model
        self._client  = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=5.0, read=300.0, write=30.0, pool=5.0
            )
        )

    async def check_available(self) -> tuple[bool, str]:
        """Check Ollama is running and our model is pulled.

        Returns (True, model_tag) on success.
        Raises OllamaNotRunningError or ModelNotFoundError.
        """
        try:
            resp = await self._client.get(
                f"{self.base_url}/api/tags", timeout=5.0
            )
            resp.raise_for_status()
        except httpx.ConnectError:
            raise OllamaNotRunningError(
                f"Ollama is not running at {self.base_url}. "
                "Start it with: ollama serve"
            )
        except httpx.TimeoutException:
            raise OllamaTimeoutError("Ollama health check timed out.")

        data   = resp.json()
        models = [m["name"] for m in data.get("models", [])]
        match  = next(
            (m for m in models
             if m.startswith(self.model) or self.model in m),
            None,
        )
        if not match:
            raise ModelNotFoundError(
                f"Model '{self.model}' not found. "
                f"Pull it with: ollama pull {self.model}\n"
                f"Available: {', '.join(models[:5]) or 'none'}"
            )
        return True, match

    async def generate_stream(
        self,
        messages:    list[dict],
        temperature: float = 0.1,
        max_tokens:  int   = 4096,
    ) -> AsyncIterator[str]:
        """Stream tokens from POST /api/chat, yielding text chunks as they arrive.

        Each NDJSON line: {"model":"...","message":{"role":"assistant","content":"..."},"done":false}
        Raises OllamaNotRunningError, OllamaTimeoutError, or AIError on failure.
        """
        payload = {
            "model":    self.model,
            "messages": messages,
            "stream":   True,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            async with self._client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=httpx.Timeout(
                    connect=5.0, read=300.0, write=30.0, pool=5.0
                ),
            ) as response:
                if response.status_code != 200:
                    body = await response.aread()
                    raise AIError(
                        f"Ollama returned HTTP {response.status_code}: "
                        f"{body.decode()[:200]}"
                    )
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    content = chunk.get("message", {}).get("content", "")
                    if content:
                        yield content
                    if chunk.get("done", False):
                        break

        except httpx.ConnectError:
            raise OllamaNotRunningError(
                f"Lost connection to Ollama at {self.base_url}."
            )
        except httpx.TimeoutException:
            raise OllamaTimeoutError(
                "Ollama response timed out. "
                "Try a smaller context or faster model."
            )

    async def generate_full(
        self,
        messages:    list[dict],
        temperature: float = 0.1,
        max_tokens:  int   = 4096,
    ) -> str:
        """Collect all streamed chunks into a single string."""
        chunks: list[str] = []
        async for chunk in self.generate_stream(messages, temperature, max_tokens):
            chunks.append(chunk)
        return "".join(chunks)

    async def generate(self, prompt: str) -> str:
        """Send a single user prompt and return the complete response string."""
        messages = [{"role": "user", "content": prompt}]
        return await self.generate_full(messages)

    async def generate_stream_to_console(
        self,
        messages:    list[dict],
        console,
        prefix:      str   = "",
        temperature: float = 0.1,
        max_tokens:  int   = 4096,
    ) -> str:
        """Stream tokens to a Rich console in real time.

        Prints each chunk with ``end=""`` for inline display.
        Returns the complete response string when done.
        """
        full: list[str] = []
        if prefix:
            console.print(prefix, end="")
        async for chunk in self.generate_stream(messages, temperature, max_tokens):
            console.print(chunk, end="", highlight=False)
            full.append(chunk)
        console.print()   # final newline
        return "".join(full)

    def estimate_tokens(self, text: str) -> int:
        """Rough estimate: 1 token ≈ 4 characters."""
        return len(text) // 4

    async def pull_model_if_needed(self, model: str) -> bool:
        """POST /api/pull with stream=True, printing progress to stdout.

        Returns True on success, False on failure.
        """
        try:
            async with self._client.stream(
                "POST",
                f"{self.base_url}/api/pull",
                json={"name": model, "stream": True},
                timeout=httpx.Timeout(
                    connect=5.0, read=600.0, write=10.0, pool=5.0
                ),
            ) as resp:
                async for line in resp.aiter_lines():
                    if line.strip():
                        try:
                            data   = json.loads(line)
                            status = data.get("status", "")
                            if status:
                                print(f"\r  {status:<60}", end="", flush=True)
                        except Exception:
                            pass
            print()
            return True
        except Exception as e:
            print(f"\nPull failed: {e}")
            return False

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()
