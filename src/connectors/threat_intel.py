"""
Connector for obtaining CISA Known Exploited Vulnerabilities (KEV) catalog and EPSS scores.
"""

import logging
from typing import Any

import httpx
from pydantic import BaseModel

from ..cache import cached
from ..config import config

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSResult(BaseModel):
    cve_id: str
    epss: float
    percentile: float
    date: str


class CisaKevResult(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    known_ransomware_campaign_use: str


class ThreatIntelConnector:
    """Connector for free vulnerability intelligence feeds: CISA KEV and EPSS."""

    @cached
    async def get_cisa_kev(self) -> dict[str, CisaKevResult]:
        """Fetch the CISA KEV catalog and return it mapped by CVE ID."""
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(CISA_KEV_URL, follow_redirects=True)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.error("Failed to fetch CISA KEV: %s", exc)
                return {}

        results: dict[str, CisaKevResult] = {}
        for item in data.get("vulnerabilities", []):
            try:
                cve_id = item["cveID"]
                results[cve_id] = CisaKevResult(
                    cve_id=cve_id,
                    vendor_project=item.get("vendorProject", ""),
                    product=item.get("product", ""),
                    vulnerability_name=item.get("vulnerabilityName", ""),
                    date_added=item.get("dateAdded", ""),
                    short_description=item.get("shortDescription", ""),
                    required_action=item.get("requiredAction", ""),
                    known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse", "Unknown")
                )
            except Exception as exc:
                logger.warning("Error parsing KEV entry: %s", exc)
        return results

    @cached
    async def get_epss(self, cve_id: str) -> EPSSResult | None:
        """Get the Exploit Prediction Scoring System (EPSS) score for a CVE."""
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(f"{EPSS_API_URL}?cve={cve_id}")
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.error("Failed to fetch EPSS for %s: %s", cve_id, exc)
                return None

        if data.get("data") and len(data["data"]) > 0:
            item = data["data"][0]
            try:
                return EPSSResult(
                    cve_id=item["cve"],
                    epss=float(item["epss"]),
                    percentile=float(item["percentile"]),
                    date=item.get("date", "")
                )
            except Exception as exc:
                logger.warning("Error parsing EPSS entry for %s: %s", cve_id, exc)
        return None
