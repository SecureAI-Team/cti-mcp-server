"""
Open Source Vulnerabilities (OSV) connector.
Provides fast, free queries against the Google OSV database (https://osv.dev)
for software supply chain and package dependencies (NPM, PyPI, Go, Rust, etc.).
"""

import logging
from typing import Any

import httpx

from ..cache import cached
from ..config import config

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns/"


class OSVConnector:
    """Query OSV.dev for package vulnerabilities."""

    def __init__(self) -> None:
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    @cached
    async def query_package(self, package_name: str, ecosystem: str = "", version: str = "") -> dict[str, Any]:
        """
        Query OSV for vulnerabilities affecting a specific package.
        ecosystem examples: PyPI, npm, crates.io, Go, Maven, NuGet.
        """
        payload: dict[str, Any] = {"package": {"name": package_name}}
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem
        if version:
            payload["version"] = version

        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.post(OSV_QUERY_URL, json=payload, follow_redirects=True)
                resp.raise_for_status()
                data = resp.json()
                
                vulns = data.get("vulns", [])
                
                # We only return the summary to save token space.
                # Detailed queries can be done via ID if needed.
                summarized = []
                for v in vulns:
                    aliases = v.get("aliases", [])
                    cve_ids = [a for a in aliases if a.startswith("CVE-")]
                    summarized.append({
                        "id": v.get("id"),
                        "cve_ids": cve_ids,
                        "summary": v.get("summary", "No summary provided"),
                        "details": (v.get("details", "")[:200] + "...") if len(v.get("details", "")) > 200 else v.get("details", ""),
                        "modified": v.get("modified"),
                        "database_specific": v.get("database_specific", {})
                    })
                    
                return {
                    "package": package_name,
                    "ecosystem": ecosystem,
                    "version": version,
                    "vulnerability_count": len(vulns),
                    "vulnerabilities": summarized
                }
            except httpx.HTTPError as exc:
                logger.error("OSV API HTTP Error: %s", exc)
                return {"error": f"OSV API error: {exc}"}
            except Exception as exc:
                logger.error("OSV API query failed: %s", exc)
                return {"error": "Internal error during OSV query"}

    @cached
    async def get_vuln_details(self, osv_id: str) -> dict[str, Any]:
        """Get full details of a specific OSV vulnerability (e.g. GHSA-xxxx-xxxx-xxxx or GO-2022-xxxx)."""
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(f"{OSV_VULNS_URL}{osv_id}", follow_redirects=True)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.error("OSV API HTTP Error for ID %s: %s", osv_id, exc)
                return {"error": f"OSV API error: {exc}"}
            except Exception as exc:
                logger.error("OSV API full details failed: %s", exc)
                return {"error": "Internal error during OSV query"}
