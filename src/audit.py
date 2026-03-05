"""
Structured audit logging for CTI MCP Server.
Records Tool calls without logging sensitive IOC values.
Outputs newline-delimited JSON (JSONL) to logs/audit.jsonl.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .config import config

logger = logging.getLogger(__name__)

# Ensure logs directory exists
_LOG_DIR = Path(config.AUDIT_LOG_DIR)
_LOG_DIR.mkdir(parents=True, exist_ok=True)
_AUDIT_FILE = _LOG_DIR / "audit.jsonl"


def _write_event(event: dict[str, Any]) -> None:
    """Append a single JSON event to the audit log (fire-and-forget)."""
    try:
        line = json.dumps(event, ensure_ascii=False, default=str) + "\n"
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)


def audit_tool_call(
    tool_name: str,
    *,
    ioc_type: str | None = None,
    verdict: str | None = None,
    sources_queried: list[str] | None = None,
    result_count: int | None = None,
    latency_ms: float | None = None,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """
    Record a Tool invocation.

    Security notes:
    - Raw indicator values (IPs, hashes, domains) are NEVER logged.
    - Only types, outcomes, and performance metrics are recorded.
    - This prevents audit logs from becoming a secondary data exfiltration vector.
    """
    event: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool_name,
    }
    if ioc_type is not None:
        event["ioc_type"] = ioc_type
    if verdict is not None:
        event["verdict"] = verdict
    if sources_queried is not None:
        event["sources_queried"] = sources_queried
    if result_count is not None:
        event["result_count"] = result_count
    if latency_ms is not None:
        event["latency_ms"] = round(latency_ms, 1)
    if error is not None:
        event["error"] = error[:200]  # truncate, never full stack
    if extra:
        event.update(extra)

    _write_event(event)


class AuditTimer:
    """Context manager that records a Tool call with latency."""

    def __init__(self, tool_name: str, **kwargs: Any) -> None:
        self._tool_name = tool_name
        self._kwargs = kwargs
        self._start: float = 0.0

    def __enter__(self) -> "AuditTimer":
        self._start = time.monotonic()
        return self

    def finish(self, **extra_kwargs: Any) -> None:
        latency_ms = (time.monotonic() - self._start) * 1000
        audit_tool_call(
            self._tool_name,
            latency_ms=latency_ms,
            **{**self._kwargs, **extra_kwargs},
        )

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        error = str(exc_val)[:100] if exc_val else None
        self.finish(error=error)
