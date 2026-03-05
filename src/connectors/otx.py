"""
AlienVault OTX API connector.
Supports: indicator lookups, pulse search, pulse details.
Enhanced with: circuit breaker, exponential-backoff retry, rate limiting.
"""

import logging
from datetime import datetime
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from ..cache import cached
from ..circuit_breaker import get_breaker
from ..config import config
from ..models import OTXContext, OTXIndicator, OTXPulse
from ..ratelimit import check_rate_limit

logger = logging.getLogger(__name__)

_HEADERS = {
    "X-OTX-API-KEY": config.OTX_API_KEY,
    "Content-Type": "application/json",
}

_CB = get_breaker("otx")


def _is_transient(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, (httpx.ConnectError, httpx.TimeoutException))


@retry(
    retry=retry_if_exception(_is_transient),
    stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    reraise=True,
)
async def _otx_get(path: str, params: dict | None = None) -> dict[str, Any] | None:
    url = f"{config.OTX_BASE_URL}{path}"
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
        resp = await client.get(url, headers=_HEADERS, params=params or {})
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()


class OTXConnector:
    """Async wrapper around AlienVault OTX API v1."""

    def __init__(self) -> None:
        self._enabled = config.is_otx_enabled()

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _get(self, path: str, params: dict | None = None) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        if not await check_rate_limit("otx"):
            raise RuntimeError("OTX rate limit exceeded. Please wait before retrying.")
        try:
            return await _CB.call(_otx_get, path, params)
        except RuntimeError:
            raise
        except httpx.HTTPStatusError as exc:
            logger.warning("OTX HTTP %s for %s", exc.response.status_code, path)
            return None
        except Exception as exc:
            logger.error("OTX request failed for %s: %s", path, exc)
            return None

    @cached
    async def get_ioc_context(self, indicator: str, ioc_type: str) -> OTXContext | None:
        if ioc_type == "ip":
            section_path = f"/indicators/IPv4/{indicator}/general"
        elif ioc_type == "domain":
            section_path = f"/indicators/domain/{indicator}/general"
        elif ioc_type == "url":
            section_path = f"/indicators/url/{indicator}/general"
        elif ioc_type == "hash":
            section_path = f"/indicators/file/{indicator}/general"
        else:
            return None

        data = await self._get(section_path)
        if not data:
            return None

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_titles = [p.get("name", "") for p in pulses[:10]]
        malware_families = list({
            mf for p in pulses for mf in p.get("malware_families", [])
        })
        pulse_count = pulse_info.get("count", 0)
        threat_score = min(100, pulse_count * 5)

        return OTXContext(
            pulse_count=pulse_count,
            pulse_titles=pulse_titles,
            malware_families=malware_families[:10],
            threat_score=threat_score,
        )

    @cached
    async def search_pulses(self, query: str, limit: int = 10) -> list[OTXPulse]:
        data = await self._get("/search/pulses", params={"q": query, "limit": limit})
        if not data:
            return []
        return [self._parse_pulse(p) for p in data.get("results", [])]

    @cached
    async def get_pulse(self, pulse_id: str) -> OTXPulse | None:
        data = await self._get(f"/pulses/{pulse_id}")
        if not data:
            return None
        return self._parse_pulse(data)

    def _parse_pulse(self, raw: dict[str, Any]) -> OTXPulse:
        indicators = [
            OTXIndicator(
                indicator=ind.get("indicator", ""),
                type=ind.get("type", ""),
                description=ind.get("description", "") or "",
            )
            for ind in raw.get("indicators", [])[:50]
        ]

        def _parse_dt(s: str | None) -> datetime | None:
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None

        return OTXPulse(
            id=raw.get("id", ""),
            name=raw.get("name", ""),
            description=raw.get("description", "") or "",
            author=raw.get("author_name", ""),
            tlp=raw.get("tlp", "white"),
            tags=raw.get("tags", []),
            malware_families=raw.get("malware_families", []),
            references=raw.get("references", [])[:10],
            indicators=indicators,
            created=_parse_dt(raw.get("created")),
            modified=_parse_dt(raw.get("modified")),
            indicator_count=raw.get("indicator_count", len(indicators)),
        )
