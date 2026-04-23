"""Per-key async rate limiter used for external API calls."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """
    Simple per-key async rate limiter.
    Ensures minimum interval between calls sharing the same key.
    Thread-safe within a single asyncio event loop.
    """

    def __init__(self) -> None:
        self._last_call: dict[str, float] = {}

    async def wait(self, key: str, min_interval: float) -> None:
        """
        Sleep if the last call with this key was less than
        min_interval seconds ago.
        Updates last-call timestamp after sleeping.
        """
        now  = time.monotonic()
        last = self._last_call.get(key, 0.0)
        gap  = now - last
        if gap < min_interval:
            await asyncio.sleep(min_interval - gap)
        self._last_call[key] = time.monotonic()

    def reset(self, key: str) -> None:
        """Clear the rate limit record for a key."""
        self._last_call.pop(key, None)

    def time_until_ready(self, key: str, min_interval: float) -> float:
        """Return seconds until this key is ready. 0.0 if ready now."""
        last = self._last_call.get(key, 0.0)
        remaining = min_interval - (time.monotonic() - last)
        return max(0.0, remaining)
