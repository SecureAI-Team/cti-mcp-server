"""
CISA ICS Advisories connector.
Parses the official CISA ICS Advisory RSS feed (no API key required).
https://www.cisa.gov/cybersecurity-advisories/ics-advisories
"""

import logging
import re
from datetime import datetime
from typing import Any

import httpx

from ..cache import cached
from ..config import config

logger = logging.getLogger(__name__)

CISA_ICS_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CISA_ICS_API_BASE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Known OT vendor keywords for matching
OT_VENDORS = {
    "siemens", "rockwell", "allen-bradley", "honeywell", "schneider",
    "abb", "emerson", "ge", "yokogawa", "mitsubishi", "omron",
    "aveva", "inductive automation", "ignition", "wonderware",
    "beckhoff", "phoenix contact", "wago", "moxa", "advantech",
    "delta", "panasonic", "b&r", "codesys", "pilz", "sick",
    "endress", "hauser", "ifm", "pepperl", "festo",
}


from pydantic import BaseModel, Field


class ICSAdvisory(BaseModel):
    """A single CISA ICS Security Advisory."""
    id: str = ""
    title: str
    link: str = ""
    published: datetime | None = None
    summary: str = ""
    affected_vendors: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cvss_max: float | None = None
    categories: list[str] = Field(default_factory=list)
    source: str = "cisa-ics"


class CISAICSConnector:
    """Connector for CISA ICS Advisories via RSS feed."""

    def __init__(self) -> None:
        self._enabled = True  # Always available, no key needed

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _fetch_rss(self) -> list[dict[str, Any]]:
        """Fetch and parse the CISA ICS RSS feed using feedparser."""
        try:
            import feedparser  # type: ignore
        except ImportError:
            logger.error("feedparser not installed. Run: pip install feedparser")
            return []

        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(CISA_ICS_RSS_URL, follow_redirects=True)
                resp.raise_for_status()
                content = resp.text
            except Exception as exc:
                logger.error("CISA RSS fetch failed: %s", exc)
                return []

        feed = feedparser.parse(content)
        return feed.get("entries", [])

    @cached
    async def get_recent(self, limit: int = 20) -> list[ICSAdvisory]:
        """Get the most recent CISA ICS advisories."""
        entries = await self._fetch_rss()
        result = []
        for entry in entries[:limit]:
            advisory = self._parse_entry(entry)
            if advisory:
                result.append(advisory)
        return result

    @cached
    async def search(
        self,
        keyword: str | None = None,
        vendor: str | None = None,
        cve_id: str | None = None,
        limit: int = 20,
    ) -> list[ICSAdvisory]:
        """Search advisories by keyword, vendor name, or CVE ID."""
        all_advisories = await self.get_recent(limit=200)
        results = []

        keyword_lower = keyword.lower() if keyword else None
        vendor_lower = vendor.lower() if vendor else None
        cve_upper = cve_id.upper() if cve_id else None

        for adv in all_advisories:
            if keyword_lower:
                haystack = f"{adv.title} {adv.summary}".lower()
                if keyword_lower not in haystack:
                    continue
            if vendor_lower:
                if not any(vendor_lower in v.lower() for v in adv.affected_vendors):
                    # Also check title/summary
                    if vendor_lower not in adv.title.lower() and vendor_lower not in adv.summary.lower():
                        continue
            if cve_upper:
                if cve_upper not in adv.cve_ids:
                    continue
            results.append(adv)
            if len(results) >= limit:
                break

        return results

    def _parse_entry(self, entry: dict[str, Any]) -> ICSAdvisory | None:
        try:
            title = entry.get("title", "")
            link = entry.get("link", "")
            summary_html = entry.get("summary", "")

            # Strip HTML tags from summary
            summary = re.sub(r"<[^>]+>", " ", summary_html).strip()
            summary = re.sub(r"\s+", " ", summary)[:1000]

            # Extract CVE IDs
            cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,}", summary_html, re.IGNORECASE)))
            cve_ids = [c.upper() for c in cve_ids]

            # Extract CVSS score
            cvss_match = re.search(r"CVSS\s+v3[^\d]*(\d+\.?\d*)", summary_html, re.IGNORECASE)
            cvss_max = float(cvss_match.group(1)) if cvss_match else None

            # Parse published date
            published = None
            if entry.get("published_parsed"):
                import calendar
                ts = calendar.timegm(entry["published_parsed"])
                published = datetime.utcfromtimestamp(ts)

            # Detect affected vendors from title/summary
            combined = f"{title} {summary}".lower()
            affected_vendors = [
                v.title() for v in OT_VENDORS
                if v in combined
            ]

            # Extract advisory ID from URL
            advisory_id = ""
            id_match = re.search(r"icsma?-\d+-\d+", link, re.IGNORECASE)
            if id_match:
                advisory_id = id_match.group(0).upper()

            # Tags/categories
            tags = [t.get("term", "") for t in entry.get("tags", [])]

            return ICSAdvisory(
                id=advisory_id,
                title=title,
                link=link,
                published=published,
                summary=summary,
                affected_vendors=affected_vendors,
                cve_ids=cve_ids,
                cvss_max=cvss_max,
                categories=tags,
            )
        except Exception as exc:
            logger.warning("Failed to parse CISA RSS entry: %s", exc)
            return None


# ── OT Vendor CPE prefix mapping ─────────────────────────────────────────────
# Used by lookup_ot_asset_cves to build NVD CPE keyword queries

OT_VENDOR_CPE_MAP: dict[str, list[str]] = {
    "siemens": ["siemens", "simatic", "sinumerik", "scalance"],
    "rockwell": ["rockwell_automation", "allen-bradley", "logix", "factorytalk"],
    "honeywell": ["honeywell", "experion"],
    "schneider": ["schneider_electric", "modicon", "ecostruxure"],
    "abb": ["abb", "symphony_plus"],
    "ge": ["ge_digital", "proficy", "cimplicity"],
    "omron": ["omron"],
    "mitsubishi": ["mitsubishi_electric", "melsec"],
    "yokogawa": ["yokogawa"],
    "beckhoff": ["beckhoff"],
    "moxa": ["moxa"],
    "advantech": ["advantech"],
    "codesys": ["codesys"],
    "aveva": ["aveva", "wonderware"],
    "emerson": ["emerson", "deltav"],
}
