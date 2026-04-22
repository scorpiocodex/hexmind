"""Per-key async rate limiter used for external API calls."""

import asyncio
import time


class RateLimiter:
    """Enforces minimum intervals between repeated calls to the same key."""

    def __init__(self) -> None:
        """Initialize with an empty last-call registry."""
        self._last_call: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def wait(self, key: str, min_interval: float) -> None:
        """Sleep until at least min_interval seconds have elapsed since the last call for key."""
        raise NotImplementedError("TODO: implement")

    def reset(self, key: str) -> None:
        """Clear the recorded last-call time for key, allowing immediate next call."""
        raise NotImplementedError("TODO: implement")
