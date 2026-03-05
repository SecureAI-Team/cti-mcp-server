"""
TTL-based in-memory cache for CTI query results.
Prevents rate-limit abuse on external APIs.
"""

import asyncio
import functools
import hashlib
import json
import logging
from typing import Any, Callable, TypeVar

from cachetools import TTLCache

from .config import config

logger = logging.getLogger(__name__)

_cache: TTLCache = TTLCache(maxsize=config.CACHE_MAX_SIZE, ttl=config.CACHE_TTL)
_lock = asyncio.Lock()


def _make_key(*args: Any, **kwargs: Any) -> str:
    """Create a stable string cache key from arbitrary arguments."""
    raw = json.dumps({"args": list(args), "kwargs": kwargs}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


async def cache_get(key: str) -> Any | None:
    async with _lock:
        value = _cache.get(key)
        if value is not None:
            logger.debug("Cache HIT: %s", key[:16])
        return value


async def cache_set(key: str, value: Any) -> None:
    async with _lock:
        _cache[key] = value
        logger.debug("Cache SET: %s", key[:16])


F = TypeVar("F", bound=Callable[..., Any])


def cached(func: F) -> F:
    """
    Async decorator that caches results of an async function.
    Cache key is derived from function name + all arguments.
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        key = _make_key(func.__qualname__, *args, **kwargs)
        cached_val = await cache_get(key)
        if cached_val is not None:
            return cached_val
        result = await func(*args, **kwargs)
        if result is not None:
            await cache_set(key, result)
        return result

    return wrapper  # type: ignore[return-value]


def get_cache_stats() -> dict[str, int]:
    return {
        "current_size": len(_cache),
        "max_size": _cache.maxsize,
        "ttl_seconds": int(_cache.ttl),
    }
