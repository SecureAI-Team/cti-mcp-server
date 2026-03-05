"""
VirusTotal v3 API connector.
Supports: file hash, IP, domain, URL lookups.
Enhanced with: circuit breaker, exponential-backoff retry, rate limiting.
"""

import base64
import logging
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
from ..models import IOCType, VTDetection
from ..ratelimit import check_rate_limit

logger = logging.getLogger(__name__)

_HEADERS = {
    "x-apikey": config.VIRUSTOTAL_API_KEY,
    "Accept": "application/json",
}

_CB = get_breaker("virustotal")

# Retry only on transient errors (5xx, connection errors); not on 4xx
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
async def _vt_get(path: str) -> dict[str, Any] | None:
    """Low-level authenticated GET with retry."""
    url = f"{config.VIRUSTOTAL_BASE_URL}{path}"
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
        resp = await client.get(url, headers=_HEADERS)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()


class VirusTotalConnector:
    """Async wrapper around VirusTotal v3 REST API."""

    def __init__(self) -> None:
        self._enabled = config.is_virustotal_enabled()

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _get(self, path: str) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        if not await check_rate_limit("virustotal"):
            raise RuntimeError("VirusTotal rate limit exceeded. Please wait before retrying.")
        try:
            return await _CB.call(_vt_get, path)
        except RuntimeError:
            raise  # Circuit breaker / rate limit — propagate
        except httpx.HTTPStatusError as exc:
            logger.warning("VT HTTP %s for %s", exc.response.status_code, path)
            return None
        except Exception as exc:
            logger.error("VT request failed for %s: %s", path, exc)
            return None

    @cached
    async def lookup_hash(self, file_hash: str) -> VTDetection | None:
        data = await self._get(f"/files/{file_hash}")
        return self._parse_stats(data)

    @cached
    async def lookup_ip(self, ip: str) -> VTDetection | None:
        data = await self._get(f"/ip_addresses/{ip}")
        return self._parse_stats(data)

    @cached
    async def lookup_domain(self, domain: str) -> VTDetection | None:
        data = await self._get(f"/domains/{domain}")
        return self._parse_stats(data)

    @cached
    async def lookup_url(self, url: str) -> VTDetection | None:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        data = await self._get(f"/urls/{url_id}")
        return self._parse_stats(data)

    @cached
    async def get_tags(self, indicator: str, ioc_type: IOCType) -> list[str]:
        data = await self._lookup_raw(indicator, ioc_type)
        if not data:
            return []
        return data.get("data", {}).get("attributes", {}).get("tags", [])

    @cached
    async def get_categories(self, indicator: str, ioc_type: IOCType) -> dict[str, str]:
        data = await self._lookup_raw(indicator, ioc_type)
        if not data:
            return {}
        return data.get("data", {}).get("attributes", {}).get("categories", {})

    async def _lookup_raw(self, indicator: str, ioc_type: IOCType) -> dict[str, Any] | None:
        if ioc_type == IOCType.HASH:
            return await self._get(f"/files/{indicator}")
        elif ioc_type == IOCType.IP:
            return await self._get(f"/ip_addresses/{indicator}")
        elif ioc_type == IOCType.DOMAIN:
            return await self._get(f"/domains/{indicator}")
        elif ioc_type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return await self._get(f"/urls/{url_id}")
        return None

    def _parse_stats(self, data: dict[str, Any] | None) -> VTDetection | None:
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats: dict[str, int] = attrs.get("last_analysis_stats", {})
        if not stats:
            return None
        total = sum(stats.values())
        return VTDetection(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=total,
        )
