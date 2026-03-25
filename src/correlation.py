"""
Cross-Intelligence Correlation Engine.

Takes a single input (CVE ID, MITRE technique ID, or IOC) and fans out to all
relevant data sources in parallel, producing a unified CorrelationResult with
an attached composite RiskScore.

Key innovation: CWE-to-ATT&CK bridge that maps CVE weakness types to MITRE
techniques automatically — enabling end-to-end CVE → technique → defense
correlation that no single upstream API provides.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from .models import CorrelationResult
from .risk_scoring import compute_risk_score

logger = logging.getLogger(__name__)

# ── CWE → ATT&CK Mapping ─────────────────────────────────────────────────────
# Curated mapping from MITRE CWE to ATT&CK Enterprise technique IDs.
# Covers the CWE Top 25 (2024) and other high-impact weakness classes.

CWE_TO_ATTACK_MAP: dict[str, list[str]] = {
    # Injection family
    "CWE-77":  ["T1059", "T1190"],           # Command Injection
    "CWE-78":  ["T1059.004", "T1190"],       # OS Command Injection
    "CWE-79":  ["T1189", "T1059.007"],       # XSS
    "CWE-89":  ["T1190", "T1505.003"],       # SQL Injection
    "CWE-94":  ["T1059", "T1190"],           # Code Injection
    "CWE-917": ["T1190", "T1059"],           # Expression Language Injection

    # Memory corruption
    "CWE-119": ["T1203", "T1068"],           # Buffer Overflow (generic)
    "CWE-120": ["T1203"],                     # Classic Buffer Overflow
    "CWE-125": ["T1203"],                     # Out-of-bounds Read
    "CWE-416": ["T1203", "T1068"],           # Use After Free
    "CWE-787": ["T1203", "T1068"],           # Out-of-bounds Write
    "CWE-190": ["T1203"],                     # Integer Overflow

    # Authentication / Access Control
    "CWE-287": ["T1078", "T1110"],           # Improper Authentication
    "CWE-306": ["T1078"],                     # Missing Authentication
    "CWE-862": ["T1548"],                     # Missing Authorization
    "CWE-863": ["T1548"],                     # Incorrect Authorization
    "CWE-269": ["T1548", "T1068"],           # Improper Privilege Management
    "CWE-798": ["T1078.001", "T1552.001"],   # Hard-coded Credentials

    # Path / File
    "CWE-22":  ["T1083", "T1005"],           # Path Traversal
    "CWE-434": ["T1505.003", "T1190"],       # Unrestricted File Upload

    # Deserialization / Data handling
    "CWE-502": ["T1059", "T1190"],           # Deserialization of Untrusted Data
    "CWE-611": ["T1190", "T1005"],           # XXE
    "CWE-918": ["T1090", "T1190"],           # SSRF

    # Cryptographic
    "CWE-327": ["T1557", "T1040"],           # Broken Crypto Algorithm
    "CWE-330": ["T1552"],                     # Insufficient Randomness

    # Information disclosure
    "CWE-200": ["T1005", "T1083"],           # Exposure of Sensitive Info
    "CWE-209": ["T1005"],                     # Error Message Info Leak
    "CWE-532": ["T1005", "T1552.001"],       # Info Exposure Through Log Files

    # Misconfiguration
    "CWE-16":  ["T1574"],                     # Configuration
    "CWE-276": ["T1574.001"],                # Incorrect Default Permissions

    # Race condition
    "CWE-362": ["T1068"],                     # TOCTOU Race Condition

    # NULL / Resource
    "CWE-476": ["T1499"],                     # NULL Pointer Dereference (DoS)
    "CWE-400": ["T1499"],                     # Uncontrolled Resource Consumption
    "CWE-770": ["T1499"],                     # Allocation Without Limits
}


def get_techniques_for_cwes(cwe_ids: list[str]) -> list[str]:
    """Return deduplicated ATT&CK technique IDs for a list of CWE IDs."""
    seen: set[str] = set()
    result: list[str] = []
    for cwe in cwe_ids:
        normalized = cwe.upper().replace("CWE-", "").strip()
        key = f"CWE-{normalized}"
        for tech_id in CWE_TO_ATTACK_MAP.get(key, []):
            if tech_id not in seen:
                seen.add(tech_id)
                result.append(tech_id)
    return result


# ── Correlation Engine ────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Fans out from a single indicator to all data sources and assembles
    a unified CorrelationResult with composite risk scoring.
    """

    def __init__(
        self,
        cve_conn: Any,
        intel_conn: Any,
        mitre_conn: Any,
        d3fend_conn: Any,
        otx_conn: Any,
        vendor_adv_conn: Any,
    ) -> None:
        self._cve = cve_conn
        self._intel = intel_conn
        self._mitre = mitre_conn
        self._d3fend = d3fend_conn
        self._otx = otx_conn
        self._vendor = vendor_adv_conn

    # ── Entry Points ──────────────────────────────────────────────────────

    async def correlate_cve(self, cve_id: str) -> CorrelationResult:
        """Full correlation starting from a CVE ID."""
        result = CorrelationResult(input_type="cve", input_value=cve_id)

        cve_data, epss_data, kev_catalog = await asyncio.gather(
            self._safe(self._cve.lookup_cve(cve_id), "nvd"),
            self._safe(self._intel.get_epss(cve_id), "epss"),
            self._safe(self._intel.get_cisa_kev(), "kev"),
            return_exceptions=True,
        )

        # Process CVE
        cvss_base = None
        if cve_data and not isinstance(cve_data, Exception):
            result.sources_consulted.append("nvd")
            result.cve = {
                "cve_id": cve_data.cve_id,
                "description": cve_data.description,
                "published": cve_data.published.isoformat() if cve_data.published else None,
                "highest_cvss": cve_data.highest_cvss_score,
                "severity": cve_data.highest_severity.value if cve_data.highest_severity else None,
                "cwe_ids": cve_data.cwe_ids,
                "affected_products": [c.cpe for c in cve_data.affected_products[:5]],
            }
            cvss_base = cve_data.highest_cvss_score
            result.cwe_ids = cve_data.cwe_ids
            result.related_cves.append(cve_id)
        else:
            result.sources_failed.append("nvd")

        # Process EPSS
        epss_val = None
        if epss_data and not isinstance(epss_data, Exception):
            result.sources_consulted.append("epss")
            result.epss = {
                "score": epss_data.epss,
                "percentile": epss_data.percentile,
                "date": epss_data.date,
            }
            epss_val = epss_data.epss
        else:
            result.sources_failed.append("epss")

        # Process KEV
        in_kev = False
        kev_due = None
        if kev_catalog and not isinstance(kev_catalog, Exception):
            result.sources_consulted.append("kev")
            kev_entry = kev_catalog.get(cve_id)
            if kev_entry:
                in_kev = True
                result.kev = {
                    "in_kev": True,
                    "vendor": kev_entry.vendor_project,
                    "product": kev_entry.product,
                    "date_added": kev_entry.date_added,
                    "required_action": kev_entry.required_action,
                    "ransomware_use": kev_entry.known_ransomware_campaign_use,
                }
            else:
                result.kev = {"in_kev": False}
        else:
            result.sources_failed.append("kev")

        # CWE → ATT&CK bridge: derive technique IDs from weakness types
        technique_ids = get_techniques_for_cwes(result.cwe_ids)

        # Fan out to MITRE, D3FEND, OTX, Vendor — all in parallel
        tasks = {}
        for tid in technique_ids[:5]:
            tasks[f"mitre:{tid}"] = self._safe(
                asyncio.to_thread(self._mitre.get_technique, tid), f"mitre:{tid}"
            )
            tasks[f"d3fend:{tid}"] = self._safe(
                self._d3fend.get_defenses_for_technique(tid), f"d3fend:{tid}"
            )

        if self._otx.enabled:
            tasks["otx"] = self._safe(
                self._otx.search_pulses(cve_id, limit=10), "otx"
            )

        tasks["vendor"] = self._safe(
            self._vendor.search(cve_id=cve_id, limit=5), "vendor_advisories"
        )

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        results_map = dict(zip(tasks.keys(), gathered))

        # Assemble MITRE techniques
        for tid in technique_ids[:5]:
            tech = results_map.get(f"mitre:{tid}")
            if tech and not isinstance(tech, Exception) and tech is not None:
                result.mitre_techniques.append({
                    "id": tech.id,
                    "name": tech.name,
                    "tactics": tech.tactics,
                    "source": "cwe_bridge",
                })
                if "mitre" not in result.sources_consulted:
                    result.sources_consulted.append("mitre")

            defenses = results_map.get(f"d3fend:{tid}")
            if defenses and not isinstance(defenses, Exception) and isinstance(defenses, dict):
                if defenses.get("defenses"):
                    result.d3fend_defenses.append({
                        "for_technique": tid,
                        "defenses": defenses["defenses"],
                        "count": defenses.get("defenses_count", 0),
                    })
                    if "d3fend" not in result.sources_consulted:
                        result.sources_consulted.append("d3fend")

        # OTX pulses
        otx_pulse_count = 0
        otx_result = results_map.get("otx")
        if otx_result and not isinstance(otx_result, Exception):
            if "otx" not in result.sources_consulted:
                result.sources_consulted.append("otx")
            for pulse in (otx_result or []):
                result.otx_pulses.append({
                    "id": pulse.id,
                    "name": pulse.name,
                    "tags": pulse.tags[:5],
                })
            otx_pulse_count = len(result.otx_pulses)

        # Vendor advisories
        vendor_count = 0
        newest_age = None
        vendor_result = results_map.get("vendor")
        if vendor_result and not isinstance(vendor_result, Exception):
            if "vendor_advisories" not in result.sources_consulted:
                result.sources_consulted.append("vendor_advisories")
            now = datetime.now(tz=timezone.utc)
            for adv in (vendor_result or []):
                result.vendor_advisories.append({
                    "vendor": adv.vendor_display,
                    "title": adv.title,
                    "severity": adv.severity,
                    "published": adv.published.isoformat() if adv.published else None,
                    "url": adv.url,
                })
                if adv.published:
                    age = (now - adv.published.replace(tzinfo=timezone.utc)
                           if adv.published.tzinfo is None
                           else now - adv.published).total_seconds() / 86400
                    if newest_age is None or age < newest_age:
                        newest_age = age
            vendor_count = len(result.vendor_advisories)

        # Compute risk score
        result.risk_score = compute_risk_score(
            cvss_base=cvss_base,
            epss_score=epss_val,
            in_kev=in_kev,
            kev_due_date=kev_due,
            vendor_advisory_count=vendor_count,
            newest_advisory_age_days=newest_age,
            otx_pulse_count=otx_pulse_count,
        )

        return result

    async def correlate_technique(self, technique_id: str) -> CorrelationResult:
        """Correlation starting from a MITRE ATT&CK technique ID."""
        result = CorrelationResult(input_type="technique", input_value=technique_id)

        tech_data, d3fend_data = await asyncio.gather(
            self._safe(asyncio.to_thread(self._mitre.get_technique, technique_id), "mitre"),
            self._safe(self._d3fend.get_defenses_for_technique(technique_id), "d3fend"),
            return_exceptions=True,
        )

        if tech_data and not isinstance(tech_data, Exception):
            result.sources_consulted.append("mitre")
            result.mitre_techniques.append({
                "id": tech_data.id,
                "name": tech_data.name,
                "description": tech_data.description[:500],
                "tactics": tech_data.tactics,
                "platforms": tech_data.platforms,
                "detection": tech_data.detection[:300] if tech_data.detection else "",
            })
        else:
            result.sources_failed.append("mitre")

        if d3fend_data and not isinstance(d3fend_data, Exception) and isinstance(d3fend_data, dict):
            result.sources_consulted.append("d3fend")
            if d3fend_data.get("defenses"):
                result.d3fend_defenses.append({
                    "for_technique": technique_id,
                    "defenses": d3fend_data["defenses"],
                    "count": d3fend_data.get("defenses_count", 0),
                })
        else:
            result.sources_failed.append("d3fend")

        # Search OTX for pulses mentioning this technique
        otx_task = None
        if self._otx.enabled:
            otx_task = self._safe(
                self._otx.search_pulses(technique_id, limit=10), "otx"
            )

        if otx_task:
            otx_result = await otx_task
            if otx_result and not isinstance(otx_result, Exception):
                result.sources_consulted.append("otx")
                for pulse in (otx_result or []):
                    result.otx_pulses.append({
                        "id": pulse.id,
                        "name": pulse.name,
                        "tags": pulse.tags[:5],
                    })

        return result

    async def correlate_ioc(self, indicator: str, ioc_type: str) -> CorrelationResult:
        """Correlation starting from an IOC (IP, domain, hash, URL)."""
        result = CorrelationResult(input_type="ioc", input_value=indicator)

        tasks: dict[str, Any] = {}
        if self._otx.enabled:
            tasks["otx_context"] = self._safe(
                self._otx.get_ioc_context(indicator, ioc_type), "otx"
            )
            tasks["otx_pulses"] = self._safe(
                self._otx.search_pulses(indicator, limit=10), "otx_pulses"
            )

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        results_map = dict(zip(tasks.keys(), gathered))

        otx_pulse_count = 0
        otx_ctx = results_map.get("otx_context")
        if otx_ctx and not isinstance(otx_ctx, Exception):
            result.sources_consulted.append("otx")
            result.ioc = {
                "indicator": indicator,
                "type": ioc_type,
                "otx_pulse_count": otx_ctx.pulse_count,
                "otx_threat_score": otx_ctx.threat_score,
                "malware_families": otx_ctx.malware_families,
            }
            otx_pulse_count = otx_ctx.pulse_count

        otx_pulses = results_map.get("otx_pulses")
        if otx_pulses and not isinstance(otx_pulses, Exception):
            for pulse in (otx_pulses or []):
                result.otx_pulses.append({
                    "id": pulse.id,
                    "name": pulse.name,
                    "tags": pulse.tags[:5],
                })

        result.risk_score = compute_risk_score(otx_pulse_count=otx_pulse_count)
        return result

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    async def _safe(coro, source_label: str) -> Any:
        """Run a coroutine and swallow exceptions, logging them."""
        try:
            return await coro
        except Exception as exc:
            logger.warning("Correlation source '%s' failed: %s", source_label, exc)
            return None
