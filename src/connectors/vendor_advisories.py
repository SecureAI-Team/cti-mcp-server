"""
Vendor Security Advisory connector.
Aggregates official security advisory feeds from major IT, OT, and AI vendors.

Vendors with RSS/Atom feeds (online):
  - Microsoft MSRC
  - Siemens ProductCERT
  - Cisco PSIRT
  - SAP
  - Oracle

Vendors without public RSS (covered via NVD CVE keyword search):
  - GE Vernova / GE Digital
  - Schneider Electric
  - Rockwell Automation
  - OpenAI
  - Anthropic
  - Google (via existing NVD)
  - Apple  (via existing NVD)

No API key required for any of these feeds.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from ..circuit_breaker import get_breaker
from ..models import ServiceStatus

logger = logging.getLogger(__name__)

# ── Vendor Registry ───────────────────────────────────────────────────────────

@dataclass
class _VendorConfig:
    name: str               # canonical lowercase key
    display_name: str       # Human-readable
    feed_url: str | None    # RSS/Atom URL; None → NVD fallback
    nvd_keywords: list[str] = field(default_factory=list)  # NVD search terms (fallback)
    category: str = "it"   # "it" | "ot" | "ai" | "cloud"
    description: str = ""


VENDOR_REGISTRY: dict[str, _VendorConfig] = {
    # ── IT / Enterprise vendors (RSS feed available) ──────────────────────────
    "microsoft": _VendorConfig(
        name="microsoft",
        display_name="Microsoft",
        feed_url="https://api.msrc.microsoft.com/update-guide/rss",
        nvd_keywords=["microsoft", "windows"],
        category="it",
        description="Microsoft Security Response Center (MSRC) — Patch Tuesday and out-of-band advisories",
    ),
    "cisco": _VendorConfig(
        name="cisco",
        display_name="Cisco",
        feed_url="https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        nvd_keywords=["cisco"],
        category="it",
        description="Cisco PSIRT — Security advisories for all Cisco products",
    ),
    "sap": _VendorConfig(
        name="sap",
        display_name="SAP",
        feed_url="https://www.sap.com/bin/rss.sap-security-notes.xml",
        nvd_keywords=["sap"],
        category="it",
        description="SAP Security Notes — Published monthly on Security Patch Day",
    ),
    "oracle": _VendorConfig(
        name="oracle",
        display_name="Oracle",
        feed_url="https://www.oracle.com/technetwork/topics/security/alerts-086861.rss",
        nvd_keywords=["oracle"],
        category="it",
        description="Oracle Critical Patch Update (CPU) and Security Alerts",
    ),
    # ── OT / ICS vendors ─────────────────────────────────────────────────────
    "siemens": _VendorConfig(
        name="siemens",
        display_name="Siemens",
        feed_url="https://cert-portal.siemens.com/productcert/rss/advisories.atom",
        nvd_keywords=["siemens"],
        category="ot",
        description="Siemens ProductCERT — Security advisories for Siemens industrial products",
    ),
    "rockwell": _VendorConfig(
        name="rockwell",
        display_name="Rockwell Automation",
        feed_url=None,
        nvd_keywords=["rockwell_automation", "allen-bradley"],
        category="ot",
        description="Rockwell Automation security advisories (via NVD)",
    ),
    "ge": _VendorConfig(
        name="ge",
        display_name="GE Vernova / GE Digital",
        feed_url=None,
        nvd_keywords=["ge vernova", "ge digital", "general electric"],
        category="ot",
        description="GE / GE Vernova industrial security advisories (via NVD)",
    ),
    "schneider": _VendorConfig(
        name="schneider",
        display_name="Schneider Electric",
        feed_url=None,
        nvd_keywords=["schneider electric"],
        category="ot",
        description="Schneider Electric security advisories (via NVD)",
    ),
    "abb": _VendorConfig(
        name="abb",
        display_name="ABB",
        feed_url=None,
        nvd_keywords=["abb"],
        category="ot",
        description="ABB industrial security advisories (via NVD)",
    ),
    "honeywell": _VendorConfig(
        name="honeywell",
        display_name="Honeywell",
        feed_url=None,
        nvd_keywords=["honeywell"],
        category="ot",
        description="Honeywell industrial security advisories (via NVD)",
    ),
    # ── AI / Cloud vendors ────────────────────────────────────────────────────
    "openai": _VendorConfig(
        name="openai",
        display_name="OpenAI",
        feed_url=None,
        nvd_keywords=["openai"],
        category="ai",
        description="OpenAI security advisories (CNA — via NVD CVE database)",
    ),
    "anthropic": _VendorConfig(
        name="anthropic",
        display_name="Anthropic",
        feed_url=None,
        nvd_keywords=["anthropic"],
        category="ai",
        description="Anthropic security advisories (via NVD CVE database)",
    ),
    "google": _VendorConfig(
        name="google",
        display_name="Google",
        feed_url=None,
        nvd_keywords=["google"],
        category="ai",
        description="Google / DeepMind security advisories (via NVD)",
    ),
}

# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class VendorAdvisory:
    vendor: str
    vendor_display: str
    title: str
    advisory_id: str
    published: datetime | None
    summary: str
    cve_ids: list[str]
    severity: str | None
    url: str
    affected_products: list[str]
    source: str  # "rss" | "nvd"


# ── Cache ─────────────────────────────────────────────────────────────────────

_ADVISORY_CACHE: dict[str, tuple[float, list[VendorAdvisory]]] = {}
_ADVISORY_CACHE_TTL = 900  # 15 minutes


def _cache_get(key: str) -> list[VendorAdvisory] | None:
    entry = _ADVISORY_CACHE.get(key)
    if entry and (time.monotonic() - entry[0]) < _ADVISORY_CACHE_TTL:
        return entry[1]
    return None


def _cache_set(key: str, data: list[VendorAdvisory]) -> None:
    _ADVISORY_CACHE[key] = (time.monotonic(), data)


# ── Helpers ───────────────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def _extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(_CVE_RE.findall(text or "")))


def _parse_severity_from_text(text: str) -> str | None:
    t = (text or "").upper()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in t:
            return sev
    return None


def _truncate(s: str, max_len: int = 400) -> str:
    s = (s or "").strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def _parse_dt(s: Any) -> datetime | None:
    """Parse feedparser time_struct or ISO string to datetime."""
    if s is None:
        return None
    try:
        if hasattr(s, "tm_year"):
            import calendar
            return datetime.fromtimestamp(calendar.timegm(s), tz=timezone.utc)
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


# ── Main Connector ────────────────────────────────────────────────────────────

class VendorAdvisoryConnector:
    """
    Aggregates security advisory feeds from major IT/OT/AI vendors.
    Uses RSS/Atom for vendors that publish feeds, NVD CVE search as fallback.
    """

    def __init__(self) -> None:
        self._breaker = get_breaker("vendor_advisories")

    # ── Public API ────────────────────────────────────────────────────────────

    def list_vendors(self) -> list[dict]:
        """Return all supported vendors with metadata."""
        return [
            {
                "name": v.name,
                "display_name": v.display_name,
                "category": v.category,
                "has_rss": v.feed_url is not None,
                "description": v.description,
            }
            for v in VENDOR_REGISTRY.values()
        ]

    async def get_recent(
        self,
        vendor: str | None = None,
        category: str | None = None,
        limit: int = 10,
    ) -> list[VendorAdvisory]:
        """
        Get recent security advisories.

        Args:
            vendor: Specific vendor name (e.g. 'microsoft', 'siemens'). None = all vendors.
            category: Filter by 'it', 'ot', or 'ai'. None = all categories.
            limit: Max number of results.
        """
        vendors = self._resolve_vendors(vendor, category)
        results: list[VendorAdvisory] = []

        per_vendor_limit = max(limit, 20)
        for vc in vendors:
            advisories = await self._fetch_vendor(vc, per_vendor_limit)
            results.extend(advisories)

        results.sort(key=lambda a: a.published or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        return results[:limit]

    async def search(
        self,
        vendor: str | None = None,
        keyword: str | None = None,
        cve_id: str | None = None,
        category: str | None = None,
        limit: int = 20,
    ) -> list[VendorAdvisory]:
        """
        Search vendor advisories by keyword or CVE ID.

        Args:
            vendor: Specific vendor. None = all vendors.
            keyword: Search term matched against title and summary.
            cve_id: Filter to advisories mentioning this CVE.
            category: Filter by 'it', 'ot', or 'ai'.
            limit: Max results.
        """
        # Fetch more than needed to allow for filtering
        raw = await self.get_recent(vendor=vendor, category=category, limit=max(limit * 5, 100))

        kw_lower = keyword.lower() if keyword else None
        cve_upper = cve_id.upper() if cve_id else None

        filtered = []
        for a in raw:
            if kw_lower:
                if kw_lower not in (a.title or "").lower() and kw_lower not in (a.summary or "").lower():
                    continue
            if cve_upper:
                if cve_upper not in [c.upper() for c in a.cve_ids]:
                    continue
            filtered.append(a)
            if len(filtered) >= limit:
                break

        return filtered

    # ── Fetch Logic ───────────────────────────────────────────────────────────

    def _resolve_vendors(
        self, vendor: str | None, category: str | None
    ) -> list[_VendorConfig]:
        if vendor:
            key = vendor.lower().strip()
            vc = VENDOR_REGISTRY.get(key)
            if not vc:
                # Partial match
                for k, v in VENDOR_REGISTRY.items():
                    if key in k or k in key:
                        vc = v
                        break
            return [vc] if vc else []

        all_v = list(VENDOR_REGISTRY.values())
        if category:
            all_v = [v for v in all_v if v.category == category.lower()]
        return all_v

    async def _fetch_vendor(
        self, vc: _VendorConfig, limit: int
    ) -> list[VendorAdvisory]:
        """Fetch advisories for one vendor, using cache."""
        cache_key = f"{vc.name}:{limit}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            if vc.feed_url:
                results = await self._fetch_rss(vc, limit)
            else:
                results = await self._fetch_nvd_fallback(vc, limit)
            _cache_set(cache_key, results)
            return results
        except Exception as exc:
            logger.warning("VendorAdvisory fetch failed for %s: %s", vc.name, exc)
            return []

    async def _fetch_rss(self, vc: _VendorConfig, limit: int) -> list[VendorAdvisory]:
        """Fetch and parse an RSS/Atom feed."""
        import feedparser  # type: ignore

        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(
                vc.feed_url,
                headers={"User-Agent": "CTI-MCP-Server/2.0 SecurityResearch"},
            )
            resp.raise_for_status()
            content = resp.text

        feed = feedparser.parse(content)
        results: list[VendorAdvisory] = []

        for entry in feed.entries[:limit]:
            raw_text = f"{entry.get('title', '')} {entry.get('summary', '')}"
            cve_ids = _extract_cves(raw_text)

            advisory = VendorAdvisory(
                vendor=vc.name,
                vendor_display=vc.display_name,
                title=entry.get("title", ""),
                advisory_id=entry.get("id", entry.get("link", ""))[-64:],  # last 64 chars
                published=_parse_dt(entry.get("published_parsed") or entry.get("updated_parsed")),
                summary=_truncate(
                    # feedparser may put HTML in summary — strip tags crudely
                    re.sub(r"<[^>]+>", " ", entry.get("summary", "")),
                    400,
                ),
                cve_ids=cve_ids,
                severity=_parse_severity_from_text(raw_text),
                url=entry.get("link", vc.feed_url or ""),
                affected_products=[],
                source="rss",
            )
            results.append(advisory)

        logger.info("VendorAdvisory RSS fetched %d items from %s", len(results), vc.display_name)
        return results

    async def _fetch_nvd_fallback(
        self, vc: _VendorConfig, limit: int
    ) -> list[VendorAdvisory]:
        """Fallback: query NVD CVE API for vendor-specific CVEs."""
        if not vc.nvd_keywords:
            return []

        keyword = vc.nvd_keywords[0]
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 20),
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()

        results: list[VendorAdvisory] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Description
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

            # CVSS severity
            metrics = cve.get("metrics", {})
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = metrics.get(key, [])
                if ms:
                    severity = ms[0].get("cvssData", {}).get("baseSeverity")
                    break

            # Published date
            pub_str = cve.get("published", "")
            published = _parse_dt(pub_str) if pub_str else None

            # References
            refs = cve.get("references", [])
            url_ref = refs[0].get("url", "") if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            results.append(VendorAdvisory(
                vendor=vc.name,
                vendor_display=vc.display_name,
                title=f"{cve_id} — {_truncate(desc, 120)}",
                advisory_id=cve_id,
                published=published,
                summary=_truncate(desc, 400),
                cve_ids=[cve_id],
                severity=severity,
                url=url_ref,
                affected_products=[],
                source="nvd",
            ))

        logger.info("VendorAdvisory NVD fallback fetched %d items for %s", len(results), vc.display_name)
        return results
