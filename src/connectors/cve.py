"""
NIST NVD CVE API v2.0 connector.
Completely free, no API key required (key raises rate limits).
"""

import logging
from datetime import datetime
from typing import Any

import httpx

from ..cache import cached
from ..config import config
from ..models import CPEMatch, CVEResult, CVSSScore, Severity

logger = logging.getLogger(__name__)


def _map_severity(s: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "NONE": Severity.NONE,
    }.get(s.upper(), Severity.UNKNOWN)


class CVEConnector:
    """Async wrapper around NIST NVD CVE API v2.0."""

    def __init__(self) -> None:
        self._headers: dict[str, str] = {}
        if config.NVD_API_KEY:
            self._headers["apiKey"] = config.NVD_API_KEY

    async def _get(self, params: dict[str, Any]) -> dict[str, Any] | None:
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(
                    config.NVD_BASE_URL, params=params, headers=self._headers
                )
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning("NVD HTTP error %s: %s", exc.response.status_code, exc)
                return None
            except Exception as exc:
                logger.error("NVD request failed: %s", exc)
                return None

    @cached
    async def lookup_cve(self, cve_id: str) -> CVEResult | None:
        """Fetch a specific CVE by its ID (e.g. CVE-2021-44228)."""
        cve_id = cve_id.strip().upper()
        data = await self._get({"cveId": cve_id})
        if not data:
            return None
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return self._parse_cve(vulns[0].get("cve", {}))

    @cached
    async def search_cves(
        self,
        keyword: str | None = None,
        severity: str | None = None,
        results_per_page: int = 10,
    ) -> list[CVEResult]:
        """Search CVEs by keyword and/or severity."""
        params: dict[str, Any] = {"resultsPerPage": min(results_per_page, 20)}
        if keyword:
            params["keywordSearch"] = keyword
        if severity and severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            params["cvssV3Severity"] = severity.upper()

        data = await self._get(params)
        if not data:
            return []
        return [
            self._parse_cve(v.get("cve", {}))
            for v in data.get("vulnerabilities", [])
            if v.get("cve")
        ]

    def _parse_cve(self, cve: dict[str, Any]) -> CVEResult:
        cve_id = cve.get("id", "")

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # Dates
        def _parse_dt(s: str | None) -> datetime | None:
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None

        # CVSS scores
        cvss_list: list[CVSSScore] = []
        metrics = cve.get("metrics", {})

        for key, version in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]:
            for m in metrics.get(key, []):
                cvss_data = m.get("cvssData", {})
                base_score = cvss_data.get("baseScore", 0.0)
                severity_str = cvss_data.get("baseSeverity", "UNKNOWN")
                if version == "2.0":
                    # CVSSv2 uses separate field
                    severity_str = m.get("baseSeverity", "UNKNOWN")
                cvss_list.append(CVSSScore(
                    version=version,
                    base_score=float(base_score),
                    severity=_map_severity(severity_str),
                    vector_string=cvss_data.get("vectorString", ""),
                    exploitability_score=m.get("exploitabilityScore"),
                    impact_score=m.get("impactScore"),
                ))

        # CWE
        cwe_ids = [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]

        # References
        references = [
            r["url"] for r in cve.get("references", [])[:10]
        ]

        # Affected CPEs
        affected: list[CPEMatch] = []
        for config_node in cve.get("configurations", []):
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    affected.append(CPEMatch(
                        cpe=match.get("criteria", ""),
                        vulnerable=match.get("vulnerable", True),
                        version_start=match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                        version_end=match.get("versionEndIncluding") or match.get("versionEndExcluding"),
                    ))

        return CVEResult(
            cve_id=cve_id,
            description=description,
            published=_parse_dt(cve.get("published")),
            last_modified=_parse_dt(cve.get("lastModified")),
            cvss=cvss_list,
            cwe_ids=cwe_ids,
            references=references,
            affected_products=affected[:20],
        )
