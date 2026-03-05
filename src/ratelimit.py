"""
Token-bucket rate limiter for external API calls.
Prevents AI Agents from exhausting API quotas.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .config import config

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """
    Thread-safe async token bucket.
    capacity: max tokens (burst)
    refill_rate: tokens added per second
    """
    capacity: float
    refill_rate: float  # tokens/second
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> bool:
        """
        Try to consume `tokens` from the bucket.
        Returns True if acquired, False if rate limit exceeded.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self.capacity,
                self._tokens + elapsed * self.refill_rate,
            )
            self._last_refill = now

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    async def wait_and_acquire(self, tokens: float = 1.0, timeout: float = 30.0) -> bool:
        """Block until a token is available or timeout expires."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self.acquire(tokens):
                return True
            wait = tokens / self.refill_rate
            await asyncio.sleep(min(wait, 0.5))
        return False


# ── Global rate limiters ─────────────────────────────────────────────────────
# VT free: 4 req/min = 1/15s; paid accounts can increase via VT_RATE_LIMIT
# OTX: generous, 60/min
# NVD: 5/30s without key, 50/30s with key

_limiters: dict[str, TokenBucket] = {
    "virustotal": TokenBucket(
        capacity=config.VT_RATE_LIMIT,
        refill_rate=config.VT_RATE_LIMIT / 60.0,
    ),
    "otx": TokenBucket(
        capacity=config.OTX_RATE_LIMIT,
        refill_rate=config.OTX_RATE_LIMIT / 60.0,
    ),
    "nvd": TokenBucket(
        capacity=5 if not config.NVD_API_KEY else 50,
        refill_rate=(5 if not config.NVD_API_KEY else 50) / 30.0,
    ),
    "cisa": TokenBucket(
        capacity=10,
        refill_rate=10 / 60.0,
    ),
}


async def check_rate_limit(source: str) -> bool:
    """
    Check and consume a token for the given data source.
    Returns True if the call is allowed, False if rate-limited.
    """
    limiter = _limiters.get(source)
    if limiter is None:
        return True  # No limiter configured = always allow
    allowed = await limiter.acquire()
    if not allowed:
        logger.warning("Rate limit exceeded for source: %s", source)
    return allowed


async def wait_rate_limit(source: str, timeout: float = 10.0) -> bool:
    """Block until a token is available for `source`, up to `timeout` seconds."""
    limiter = _limiters.get(source)
    if limiter is None:
        return True
    return await limiter.wait_and_acquire(timeout=timeout)


def get_rate_limit_status() -> dict[str, dict]:
    """Return current token counts for status display."""
    return {
        name: {
            "capacity": b.capacity,
            "available_tokens": round(b._tokens, 2),
            "refill_rate_per_min": round(b.refill_rate * 60, 1),
        }
        for name, b in _limiters.items()
    }
