"""
Circuit breaker for external API connectors.
Prevents cascading failures when upstream services are down.

States:
  CLOSED   → Normal operation. Failures counted.
  OPEN     → API assumed failed. Requests rejected immediately.
  HALF_OPEN → Trial period after recovery_timeout. One probe request allowed.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class CBState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """
    Per-datasource circuit breaker.

    failure_threshold: consecutive failures to trip
    recovery_timeout:  seconds to wait before half-open probe
    """
    name: str
    failure_threshold: int = 3
    recovery_timeout: float = 60.0

    _state: CBState = field(default=CBState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _lock: asyncio.Lock = field(init=False)

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CBState:
        return self._state

    async def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Execute `func` through the circuit breaker.
        Raises RuntimeError if the circuit is OPEN.
        """
        async with self._lock:
            if self._state == CBState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    logger.info("[CB:%s] Transitioning OPEN → HALF_OPEN", self.name)
                    self._state = CBState.HALF_OPEN
                else:
                    raise RuntimeError(
                        f"Circuit breaker OPEN for '{self.name}'. "
                        f"Retry in {self.recovery_timeout - elapsed:.0f}s."
                    )

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as exc:
            await self._on_failure(exc)
            raise

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state in (CBState.HALF_OPEN, CBState.OPEN):
                logger.info("[CB:%s] Recovery confirmed → CLOSED", self.name)
            self._state = CBState.CLOSED
            self._failure_count = 0

    async def _on_failure(self, exc: Exception) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            logger.warning(
                "[CB:%s] Failure %d/%d: %s",
                self.name, self._failure_count, self.failure_threshold, exc
            )
            if self._failure_count >= self.failure_threshold:
                if self._state != CBState.OPEN:
                    logger.error(
                        "[CB:%s] TRIPPED → OPEN after %d failures",
                        self.name, self._failure_count
                    )
                self._state = CBState.OPEN

    def get_status(self) -> dict:
        return {
            "state": self._state.value,
            "failure_count": self._failure_count,
            "recovery_timeout_s": self.recovery_timeout,
        }


# ── Global circuit breakers (one per external data source) ───────────────────

_breakers: dict[str, CircuitBreaker] = {
    "virustotal": CircuitBreaker("virustotal", failure_threshold=3, recovery_timeout=60),
    "otx": CircuitBreaker("otx", failure_threshold=3, recovery_timeout=60),
    "nvd": CircuitBreaker("nvd", failure_threshold=3, recovery_timeout=120),
    "cisa": CircuitBreaker("cisa", failure_threshold=3, recovery_timeout=120),
}


def get_breaker(source: str) -> CircuitBreaker:
    return _breakers[source]


def get_all_breaker_status() -> dict[str, dict]:
    return {name: cb.get_status() for name, cb in _breakers.items()}
