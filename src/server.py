"""
CTI MCP Server — Enhanced main entrypoint.
v2: ICS/OT tools, input validation, audit logging, concurrent queries, circuit breakers.
"""

import asyncio
import logging
import threading
from datetime import datetime
from typing import Annotated

from fastmcp import FastMCP
from mcp.types import PromptMessage, TextContent
from pydantic import Field

from .audit import AuditTimer, audit_tool_call
from .cache import get_cache_stats
from .circuit_breaker import get_all_breaker_status
from .config import config, setup_logging
from .connectors.cisa_ics import CISAICSConnector, OT_VENDOR_CPE_MAP
from .connectors.cve import CVEConnector
from .connectors.mitre_atlas import MitreAtlasConnector, OWASP_LLM_TOP10, AI_FRAMEWORK_CVE_MAP
from .connectors.mitre_attack import MitreAttackConnector
from .connectors.mitre_ics import MitreICSConnector
from .connectors.mac_oui import MacOUIConnector
from .connectors.mitre_d3fend import MitreD3fendConnector
from .connectors.osv import OSVConnector
from .connectors.otx import OTXConnector
from .connectors.threat_intel import ThreatIntelConnector
from .connectors.vendor_advisories import VendorAdvisoryConnector, VENDOR_REGISTRY
from .connectors.virustotal import VirusTotalConnector
from .correlation import CorrelationEngine, CWE_TO_ATTACK_MAP, get_techniques_for_cwes
from .models import (
    DataSourceStatus,
    IOCResult,
    IOCType,
    ServiceStatus,
)
from .ratelimit import get_rate_limit_status
from .risk_scoring import compute_risk_score
from .validators import (
    ValidationError,
    sanitize_error,
    validate_cve_id,
    validate_ioc,
    validate_query_string,
    validate_technique_id,
)

# ── Setup ─────────────────────────────────────────────────────────────────────

setup_logging()
logger = logging.getLogger(__name__)

mcp = FastMCP(
    name=config.MCP_SERVER_NAME,
    instructions=(
        "This is a Cyber Threat Intelligence (CTI) MCP server with ICS/OT support. "
        "Tools available: IOC lookup (IP/domain/hash/URL), CVE queries, "
        "MITRE ATT&CK Enterprise & ICS techniques, CISA ICS advisories, "
        "Vendor Security Advisories (Microsoft/Siemens/Cisco/SAP/Oracle/GE/Rockwell/OpenAI/...), "
        "and OTX pulses. "
        "Read `cti://status` first to see which data sources are active."
    ),
)

# ── Connector singletons ──────────────────────────────────────────────────────

_vt = VirusTotalConnector()
_otx = OTXConnector()
_mitre = MitreAttackConnector()
_mitre_ics = MitreICSConnector()
_atlas = MitreAtlasConnector()
_cve = CVEConnector()
_cisa = CISAICSConnector()
_intel = ThreatIntelConnector()
_mac = MacOUIConnector()
_osv = OSVConnector()
_d3fend = MitreD3fendConnector()
_vendor_adv = VendorAdvisoryConnector()

_correlator = CorrelationEngine(
    cve_conn=_cve,
    intel_conn=_intel,
    mitre_conn=_mitre,
    d3fend_conn=_d3fend,
    otx_conn=_otx,
    vendor_adv_conn=_vendor_adv,
)


# ── Startup warmup (background thread) ───────────────────────────────────────

def _warmup() -> None:
    """Pre-load STIX/YAML data 5 seconds after server starts."""
    import time
    time.sleep(5)
    logger.info("Background warmup: loading MITRE ATT&CK Enterprise data...")
    _mitre._load()
    logger.info("Background warmup: loading MITRE ATT&CK for ICS data...")
    _mitre_ics._load()
    logger.info("Background warmup: loading MITRE ATLAS AI threat data...")
    _atlas._load()
    logger.info("Background warmup complete.")


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — IOC
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def lookup_ioc(
    indicator: Annotated[str, Field(description="The IOC value (IP, domain, URL, or file hash)")],
    ioc_type: Annotated[str, Field(description="Type of IOC: 'ip', 'domain', 'url', or 'hash'")],
) -> dict:
    """
    Query threat intelligence for an Indicator of Compromise.
    Queries VirusTotal and AlienVault OTX concurrently and returns an aggregated verdict.

    Examples:
    - indicator="8.8.8.8", ioc_type="ip"
    - indicator="example.com", ioc_type="domain"
    - indicator="44d88612fea8a8f36de82e1278abb02f", ioc_type="hash"
    - indicator="http://malicious.com/payload", ioc_type="url"
    """
    with AuditTimer("lookup_ioc", ioc_type=ioc_type) as t:
        # ── Input validation ─────────────────────────────────
        try:
            indicator = validate_ioc(indicator, ioc_type)
            ioc_type_enum = IOCType(ioc_type.lower())
        except ValidationError as exc:
            audit_tool_call("lookup_ioc", ioc_type=ioc_type, error=str(exc))
            return {"error": str(exc)}
        except ValueError as exc:
            return {"error": sanitize_error(exc)}

        result = IOCResult(indicator=indicator, ioc_type=ioc_type_enum)

        # ── Concurrent queries ────────────────────────────────
        async def query_vt() -> None:
            if not _vt.enabled:
                result.sources_unavailable.append("virustotal (no API key)")
                return
            try:
                if ioc_type_enum == IOCType.HASH:
                    result.vt = await _vt.lookup_hash(indicator)
                elif ioc_type_enum == IOCType.IP:
                    result.vt = await _vt.lookup_ip(indicator)
                elif ioc_type_enum == IOCType.DOMAIN:
                    result.vt = await _vt.lookup_domain(indicator)
                elif ioc_type_enum == IOCType.URL:
                    result.vt = await _vt.lookup_url(indicator)
                result.vt_tags = await _vt.get_tags(indicator, ioc_type_enum)
                result.sources_queried.append("virustotal")
            except RuntimeError as exc:
                result.sources_unavailable.append(f"virustotal ({sanitize_error(exc)})")
            except Exception as exc:
                logger.error("VT lookup failed: %s", exc)
                result.sources_unavailable.append("virustotal (error)")

        async def query_otx() -> None:
            if not _otx.enabled:
                result.sources_unavailable.append("otx (no API key)")
                return
            try:
                result.otx = await _otx.get_ioc_context(indicator, ioc_type)
                result.sources_queried.append("otx")
            except RuntimeError as exc:
                result.sources_unavailable.append(f"otx ({sanitize_error(exc)})")
            except Exception as exc:
                logger.error("OTX lookup failed: %s", exc)
                result.sources_unavailable.append("otx (error)")

        # Run VT + OTX in parallel
        await asyncio.gather(query_vt(), query_otx())

        result.compute_verdict()
        t.finish(verdict=result.verdict, sources_queried=result.sources_queried)
        return result.model_dump(mode="json")


@mcp.tool()
async def get_threat_summary(
    indicator: Annotated[str, Field(description="The IOC value (IP, domain, URL, or file hash)")],
    ioc_type: Annotated[str, Field(description="Type of IOC: 'ip', 'domain', 'url', or 'hash'")],
) -> dict:
    """
    Get a concise, human-readable threat summary for an IOC.
    Combines all available sources into a Markdown report.
    """
    raw = await lookup_ioc(indicator=indicator, ioc_type=ioc_type)
    if "error" in raw:
        return raw

    lines = [
        f"## Threat Summary: {indicator} ({ioc_type.upper()})",
        f"**Verdict**: {raw.get('verdict', 'unknown').upper()}",
        f"**Threat Score**: {raw.get('threat_score', 0)}/100",
    ]

    vt = raw.get("vt")
    if vt and vt.get("total", 0) > 0:
        lines.append("\n### VirusTotal")
        lines.append(f"- Detection: {vt['malicious']}/{vt['total']} engines")
        if vt.get("suspicious"):
            lines.append(f"- Suspicious: {vt['suspicious']} engines")
        tags = raw.get("vt_tags", [])
        if tags:
            lines.append(f"- Tags: {', '.join(tags[:10])}")

    otx = raw.get("otx")
    if otx and otx.get("pulse_count", 0) > 0:
        lines.append("\n### AlienVault OTX")
        lines.append(f"- Referenced in {otx['pulse_count']} pulse(s)")
        if otx.get("malware_families"):
            lines.append(f"- Related malware: {', '.join(otx['malware_families'][:5])}")
        if otx.get("pulse_titles"):
            lines.append(f"- Recent pulses: {', '.join(otx['pulse_titles'][:3])}")

    sources = raw.get("sources_queried", [])
    unavailable = raw.get("sources_unavailable", [])
    lines.append(f"\n**Sources queried**: {', '.join(sources) or 'none'}")
    if unavailable:
        lines.append(f"**Unavailable**: {', '.join(unavailable)}")

    return {"summary": "\n".join(lines), "raw": raw}


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — CVE
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def lookup_cve(
    cve_id: Annotated[str, Field(description="CVE identifier, e.g. CVE-2021-44228 (Log4Shell)")],
) -> dict:
    """
    Look up detailed CVE vulnerability information from NIST NVD.
    Returns CVSS scores, description, affected products, and references.
    No API key required.
    """
    with AuditTimer("lookup_cve") as t:
        try:
            cve_id = validate_cve_id(cve_id)
        except ValidationError as exc:
            return {"error": str(exc)}

        result = await _cve.lookup_cve(cve_id)
        if not result:
            t.finish(error="not_found")
            return {"error": f"CVE '{cve_id}' not found in NVD database."}
            
        data = result.model_dump(mode="json")
        
        # Concurrently enrich with EPSS and KEV if available
        async def enrich():
            epss_result, kev_data = await asyncio.gather(
                _intel.get_epss(cve_id),
                _intel.get_cisa_kev()
            )
            if epss_result:
                data["epss"] = epss_result.model_dump(mode="json")
            if kev_data and cve_id in kev_data:
                data["cisa_kev"] = kev_data[cve_id].model_dump(mode="json")
        
        await enrich()

        t.finish(result_count=1)
        return data


@mcp.tool()
async def get_epss_score(
    cve_id: Annotated[str, Field(description="CVE ID to look up EPSS score for (e.g. CVE-2021-44228)")],
) -> dict:
    """
    Get the Exploit Prediction Scoring System (EPSS) score for a CVE.
    EPSS estimates the probability of a vulnerability being exploited in the wild.
    """
    with AuditTimer("get_epss_score") as t:
        try:
            cve_id = validate_cve_id(cve_id)
        except ValidationError as exc:
            return {"error": str(exc)}

        result = await _intel.get_epss(cve_id)
        if not result:
            t.finish(error="not_found")
            return {"error": f"EPSS score not found for '{cve_id}'."}
        
        t.finish(result_count=1)
        return result.model_dump(mode="json")


@mcp.tool()
async def is_cve_known_exploited(
    cve_id: Annotated[str, Field(description="CVE ID to check against CISA KEV catalog")],
) -> dict:
    """
    Check if a CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.
    Being in KEV means attackers are actively using this vulnerability in the wild.
    """
    with AuditTimer("is_cve_known_exploited") as t:
        try:
            cve_id = validate_cve_id(cve_id)
        except ValidationError as exc:
            return {"error": str(exc)}

        kev_data = await _intel.get_cisa_kev()
        if not kev_data:
            return {"error": "Failed to fetch CISA KEV catalog."}
            
        if cve_id in kev_data:
            t.finish(result_count=1, verdict="active_exploit")
            return {
                "cve_id": cve_id,
                "is_known_exploited": True,
                "kev_details": kev_data[cve_id].model_dump(mode="json")
            }
        
        t.finish(result_count=0, verdict="not_in_kev")
        return {"cve_id": cve_id, "is_known_exploited": False}


@mcp.tool()
async def search_cves(
    keyword: Annotated[str | None, Field(description="Keyword to search in CVE descriptions")] = None,
    severity: Annotated[str | None, Field(description="Filter by: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search CVE vulnerabilities by keyword and/or severity.
    No API key required.

    Examples:
    - keyword="log4j", severity="CRITICAL"
    - keyword="siemens PLC", severity="HIGH"    ← OT/ICS CVE search
    - severity="CRITICAL", limit=5
    """
    if not keyword and not severity:
        return {"error": "Provide at least one of: keyword, severity"}
    try:
        if keyword:
            keyword = validate_query_string(keyword, "keyword")
    except ValidationError as exc:
        return {"error": str(exc)}

    with AuditTimer("search_cves") as t:
        results = await _cve.search_cves(keyword=keyword, severity=severity, results_per_page=limit)
        t.finish(result_count=len(results))
        return {
            "count": len(results),
            "cves": [
                {
                    "id": r.cve_id,
                    "severity": r.highest_severity.value,
                    "cvss_score": r.highest_cvss_score,
                    "description": r.description[:300] + "..." if len(r.description) > 300 else r.description,
                    "published": r.published.isoformat() if r.published else None,
                }
                for r in results
            ],
        }


@mcp.tool()
async def lookup_osv_package(
    package: Annotated[str, Field(description="Name of the software package (e.g. 'log4j-core', 'requests')")],
    ecosystem: Annotated[str | None, Field(description="Optional ecosystem (e.g. 'PyPI', 'npm', 'Maven', 'Go')")] = None,
    version: Annotated[str | None, Field(description="Optional specific version version check (e.g. '1.0.0')")] = None,
) -> dict:
    """
    Look up vulnerabilities for a given open-source software component/package utilizing the OSV database.
    This is extremely useful for Supply Chain Security (SCS) and SBOM vulnerability analysis.
    """
    with AuditTimer("lookup_osv_package") as t:
        try:
            package = validate_query_string(package, "package")
            if ecosystem:
                ecosystem = validate_query_string(ecosystem, "ecosystem")
        except ValidationError as exc:
            return {"error": str(exc)}

        result = await _osv.query_package(package_name=package, ecosystem=ecosystem, version=version)
        t.finish(result_count=result.get("vulnerability_count", 0))
        return result


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — MITRE ATT&CK (Enterprise)
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_mitre_technique(
    technique_id: Annotated[str, Field(description="ATT&CK technique ID, e.g. T1059 or T1059.001")],
) -> dict:
    """
    Get MITRE ATT&CK Enterprise technique details.
    Covers IT/traditional systems. For OT/ICS use get_mitre_ics_technique.
    No API key required — uses locally cached STIX data.
    """
    try:
        technique_id = validate_technique_id(technique_id)
    except ValidationError as exc:
        return {"error": str(exc)}

    result = _mitre.get_technique(technique_id)
    if not result:
        return {"error": f"Technique '{technique_id}' not found in ATT&CK Enterprise. "
                         f"For ICS techniques (T08xx), use get_mitre_ics_technique."}
    return result.model_dump(mode="json")


@mcp.tool()
async def search_mitre_techniques(
    query: Annotated[str, Field(description="Search term for ATT&CK Enterprise techniques")],
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search MITRE ATT&CK Enterprise techniques by name or description.
    For ICS/OT techniques, use search_mitre_ics_techniques.
    No API key required.
    """
    try:
        query = validate_query_string(query)
    except ValidationError as exc:
        return {"error": str(exc)}

    results = _mitre.search_techniques(query, limit=limit)
    return {
        "count": len(results),
        "techniques": [
            {
                "id": t.id,
                "name": t.name,
                "tactics": t.tactics,
                "platforms": t.platforms,
                "description_snippet": t.description[:200] + "..." if len(t.description) > 200 else t.description,
                "url": t.url,
            }
            for t in results
        ],
    }


@mcp.tool()
async def get_mitre_d3fend_countermeasures(
    technique_id: Annotated[str, Field(description="ATT&CK Technique ID (e.g., 'T1059') to find defenses for.")],
) -> dict:
    """
    Query the MITRE D3FEND knowledge base for defensive countermeasures tailored against a specific ATT&CK technique.
    This tells the security teams EXACTLY what mechanisms they should deploy to defend against the technique.
    """
    with AuditTimer("get_mitre_d3fend_countermeasures") as t:
        try:
            technique_id = validate_technique_id(technique_id)
        except ValidationError as exc:
            return {"error": str(exc)}

        result = await _d3fend.get_defenses_for_technique(technique_id)
        t.finish(result_count=result.get("defenses_count", 0))
        return result


@mcp.tool()
async def search_threat_actors(
    query: Annotated[str, Field(description="Search term for threat actor / APT groups")],
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search MITRE ATT&CK Enterprise threat actors (APT groups) by name or alias.
    Useful for attributing behaviors to specific threat groups (e.g., 'Sandworm', 'Lazarus').
    """
    try:
        query = validate_query_string(query)
    except ValidationError as exc:
        return {"error": str(exc)}

    results = _mitre.search_groups(query, limit=limit)
    return {
        "count": len(results),
        "groups": [
            {
                "id": g.id,
                "name": g.name,
                "aliases": g.aliases,
                "description_snippet": g.description[:400] + "..." if len(g.description) > 400 else g.description,
                "url": g.url,
            }
            for g in results
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — MITRE ATT&CK for ICS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_mitre_ics_technique(
    technique_id: Annotated[str, Field(description="ATT&CK for ICS technique ID, e.g. T0855 or T0814")],
) -> dict:
    """
    Get MITRE ATT&CK for ICS technique details.
    Covers OT/SCADA-specific attack techniques (T08xx range).
    Includes Modbus, DNP3, and SCADA-specific behaviors.
    No API key required — uses locally cached STIX data.

    Common ICS techniques:
    - T0855: Unauthorized Command Message
    - T0814: Denial of Control
    - T0828: Loss of Safety
    - T0816: Device Restart/Shutdown
    """
    try:
        technique_id = validate_technique_id(technique_id)
    except ValidationError as exc:
        return {"error": str(exc)}

    result = _mitre_ics.get_technique(technique_id)
    if not result:
        return {"error": f"ICS technique '{technique_id}' not found. "
                         f"ICS techniques use T08xx range (e.g. T0855)."}
    return result.model_dump(mode="json")


@mcp.tool()
async def search_mitre_ics_techniques(
    query: Annotated[str, Field(description="Search term for ATT&CK for ICS techniques")],
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search MITRE ATT&CK for ICS techniques by name or description.
    Covers OT/SCADA/ICS-specific attack patterns.
    No API key required.

    Examples:
    - query="modbus"
    - query="safety system"
    - query="loss of control"
    - query="historian"
    """
    try:
        query = validate_query_string(query)
    except ValidationError as exc:
        return {"error": str(exc)}

    results = _mitre_ics.search_techniques(query, limit=limit)
    audit_tool_call("search_mitre_ics_techniques", result_count=len(results))
    return {
        "count": len(results),
        "techniques": [
            {
                "id": t.id,
                "name": t.name,
                "tactics": t.tactics,
                "platforms": t.platforms,
                "description_snippet": t.description[:250] + "..." if len(t.description) > 250 else t.description,
                "url": t.url,
            }
            for t in results
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — CISA ICS Advisories
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def search_ics_advisories(
    keyword: Annotated[str | None, Field(description="Keyword to search in advisory title/summary")] = None,
    vendor: Annotated[str | None, Field(description="OT vendor name, e.g. 'Siemens', 'Rockwell', 'Honeywell'")] = None,
    cve_id: Annotated[str | None, Field(description="CVE ID to find associated advisories")] = None,
    limit: Annotated[int, Field(description="Max results (1-50)", ge=1, le=50)] = 20,
) -> dict:
    """
    Search CISA ICS Security Advisories for OT/SCADA vulnerabilities.
    No API key required — uses the official CISA RSS feed.

    Examples:
    - vendor="Siemens"                              ← All Siemens ICS advisories
    - vendor="Rockwell", keyword="remote code"      ← Rockwell RCE advisories
    - cve_id="CVE-2022-38773"                       ← Find advisory for specific CVE
    - keyword="SCADA"                               ← All SCADA-related advisories
    """
    if not keyword and not vendor and not cve_id:
        return {"error": "Provide at least one of: keyword, vendor, cve_id"}

    try:
        if keyword:
            keyword = validate_query_string(keyword, "keyword")
        if vendor:
            vendor = validate_query_string(vendor, "vendor")
        if cve_id:
            cve_id = validate_cve_id(cve_id)
    except ValidationError as exc:
        return {"error": str(exc)}

    with AuditTimer("search_ics_advisories") as t:
        results = await _cisa.search(keyword=keyword, vendor=vendor, cve_id=cve_id, limit=limit)
        t.finish(result_count=len(results))
        return {
            "count": len(results),
            "advisories": [
                {
                    "id": a.id,
                    "title": a.title,
                    "link": a.link,
                    "published": a.published.isoformat() if a.published else None,
                    "affected_vendors": a.affected_vendors,
                    "cve_ids": a.cve_ids,
                    "cvss_max": a.cvss_max,
                    "summary": a.summary[:400] + "..." if len(a.summary) > 400 else a.summary,
                }
                for a in results
            ],
        }


@mcp.tool()
async def get_recent_ics_advisories(
    limit: Annotated[int, Field(description="Number of most recent advisories (1-50)", ge=1, le=50)] = 10,
) -> dict:
    """
    Get the most recent CISA ICS Security Advisories.
    Useful for staying current on OT/SCADA vulnerabilities.
    No API key required.
    """
    with AuditTimer("get_recent_ics_advisories") as t:
        results = await _cisa.get_recent(limit=limit)
        t.finish(result_count=len(results))
        return {
            "count": len(results),
            "advisories": [
                {
                    "id": a.id,
                    "title": a.title,
                    "link": a.link,
                    "published": a.published.isoformat() if a.published else None,
                    "affected_vendors": a.affected_vendors,
                    "cve_ids": a.cve_ids,
                    "cvss_max": a.cvss_max,
                }
                for a in results
            ],
        }


@mcp.tool()
async def lookup_ot_asset_cves(
    vendor: Annotated[str, Field(description="OT vendor name (e.g. 'siemens', 'rockwell', 'honeywell')")],
    product: Annotated[str | None, Field(description="Product name/keyword (e.g. 's71200', 'logix', 'scalance')")] = None,
    severity: Annotated[str | None, Field(description="Severity filter: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search for CVEs affecting specific OT/ICS vendor equipment via NVD.
    Supports major ICS/OT vendors and their product lines.
    No API key required.

    Examples:
    - vendor="siemens", product="s7", severity="CRITICAL"
    - vendor="rockwell", product="logix"
    - vendor="schneider", severity="HIGH"
    - vendor="honeywell"

    Supported vendors: siemens, rockwell, honeywell, schneider, abb, ge,
    omron, mitsubishi, yokogawa, beckhoff, moxa, advantech, codesys, aveva, emerson
    """
    vendor_lower = vendor.lower().strip()
    cpe_keywords = OT_VENDOR_CPE_MAP.get(vendor_lower)

    if not cpe_keywords:
        # Try partial match
        for key, keywords in OT_VENDOR_CPE_MAP.items():
            if vendor_lower in key or key in vendor_lower:
                cpe_keywords = keywords
                break

    if not cpe_keywords:
        available = sorted(OT_VENDOR_CPE_MAP.keys())
        return {
            "error": f"Vendor '{vendor}' not in OT vendor map.",
            "supported_vendors": available,
        }

    # Build search keyword: "vendor_name product_name"
    search_kw = cpe_keywords[0]
    if product:
        try:
            product = validate_query_string(product, "product")
        except ValidationError as exc:
            return {"error": str(exc)}
        search_kw = f"{search_kw} {product}"

    with AuditTimer("lookup_ot_asset_cves") as t:
        results = await _cve.search_cves(
            keyword=search_kw, severity=severity, results_per_page=limit
        )
        t.finish(result_count=len(results))
        return {
            "vendor": vendor,
            "product_filter": product,
            "severity_filter": severity,
            "count": len(results),
            "cves": [
                {
                    "id": r.cve_id,
                    "severity": r.highest_severity.value,
                    "cvss_score": r.highest_cvss_score,
                    "description": r.description[:300] + "..." if len(r.description) > 300 else r.description,
                    "published": r.published.isoformat() if r.published else None,
                    "affected_products": [c.cpe for c in r.affected_products[:5]],
                }
                for r in results
            ],
        }


@mcp.tool()
async def lookup_mac_vendor(
    mac_address: Annotated[str, Field(description="MAC address to look up (e.g. '00:1A:2B:3C:4D:5E' or '00-1A-2B-3C-4D-5E')")],
) -> dict:
    """
    Look up the hardware manufacturer (vendor) for a given MAC address.
    Useful for fingerprinting unknown devices in OT/ICS or IT networks.
    """
    with AuditTimer("lookup_mac_vendor") as t:
        result = await _mac.lookup_mac(mac_address)
        t.finish(result_count=1 if result.get("found") else 0)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — OTX
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_otx_pulse(
    pulse_id: Annotated[str, Field(description="OTX Pulse ID (alphanumeric string from OTX URL)")],
) -> dict:
    """
    Get detailed information for a specific AlienVault OTX threat pulse.
    Requires OTX API key.
    """
    if not _otx.enabled:
        return {"error": "OTX connector is not enabled. Set OTX_API_KEY in .env"}

    with AuditTimer("get_otx_pulse") as t:
        result = await _otx.get_pulse(pulse_id)
        if not result:
            t.finish(error="not_found")
            return {"error": f"OTX pulse '{pulse_id}' not found."}
        t.finish(result_count=1)
        return result.model_dump(mode="json")


@mcp.tool()
async def search_otx_pulses(
    query: Annotated[str, Field(description="Search query for OTX threat pulses")],
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search AlienVault OTX threat pulses by keyword.
    Requires OTX API key.

    ICS-relevant examples:
    - query="ICS SCADA"
    - query="Modbus exploitation"
    - query="industrial control system"
    """
    if not _otx.enabled:
        return {"error": "OTX connector is not enabled. Set OTX_API_KEY in .env"}
    try:
        query = validate_query_string(query)
    except ValidationError as exc:
        return {"error": str(exc)}

    with AuditTimer("search_otx_pulses") as t:
        results = await _otx.search_pulses(query, limit=limit)
        t.finish(result_count=len(results))
        return {
            "count": len(results),
            "pulses": [
                {
                    "id": p.id,
                    "name": p.name,
                    "author": p.author,
                    "tags": p.tags[:5],
                    "malware_families": p.malware_families[:5],
                    "indicator_count": p.indicator_count,
                    "tlp": p.tlp,
                    "created": p.created.isoformat() if p.created else None,
                }
                for p in results
            ],
        }


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCES
# ══════════════════════════════════════════════════════════════════════════════

@mcp.resource("cti://status")
async def resource_status() -> str:
    """Service status — data sources, circuit breakers, rate limits, and cache."""
    cb_status = get_all_breaker_status()
    rl_status = get_rate_limit_status()
    cache_stats = get_cache_stats()

    data_sources = [
        DataSourceStatus(name="virustotal", enabled=_vt.enabled,
                         description="VirusTotal v3 API — IOC reputation"),
        DataSourceStatus(name="otx", enabled=_otx.enabled,
                         description="AlienVault OTX — threat pulses and IOC context"),
        DataSourceStatus(name="nvd-cve", enabled=True,
                         description="NIST NVD CVE API v2.0 — vulnerability details"),
        DataSourceStatus(name="mitre-attack", enabled=True,
                         description="MITRE ATT&CK Enterprise — IT/traditional techniques"),
        DataSourceStatus(name="mitre-ics", enabled=True,
                         description="MITRE ATT&CK for ICS — OT/SCADA techniques"),
        DataSourceStatus(name="mitre-atlas", enabled=True,
                         description="MITRE ATLAS AI Threat Matrix — LLM/ML attack techniques"),
        DataSourceStatus(name="cisa-ics", enabled=True,
                         description="CISA ICS Advisories — OT/ICS security bulletins"),
        DataSourceStatus(name="epss-kev", enabled=True,
                         description="EPSS & CISA KEV — Active exploit prediction and tracking"),
        DataSourceStatus(name="mac-oui", enabled=_mac.enabled,
                         description="IEEE MAC OUI — OT/IT hardware fingerprinting"),
        DataSourceStatus(name="osv", enabled=_osv.enabled,
                         description="OSV Database — Software supply chain vulnerabilities"),
        DataSourceStatus(name="d3fend", enabled=_d3fend.enabled,
                         description="MITRE D3FEND — Defensive mechanisms & countermeasures"),
    ]
    status = ServiceStatus(
        server_name=config.MCP_SERVER_NAME,
        data_sources=data_sources,
        cache_ttl_seconds=config.CACHE_TTL,
    )

    lines = [
        "# CTI MCP Server Status",
        f"**Server**: {status.server_name} v{status.version}",
        f"**Cache**: {cache_stats['current_size']}/{cache_stats['max_size']} entries, TTL={cache_stats['ttl_seconds']}s",
        "",
        "## Data Sources",
    ] + [
        f"- {'✅' if ds.enabled else '❌'} **{ds.name}**: {ds.description}"
        for ds in data_sources
    ] + [
        "",
        "## Circuit Breakers",
    ] + [
        f"- **{name}**: state={s['state']}, failures={s['failure_count']}"
        for name, s in cb_status.items()
    ] + [
        "",
        "## Rate Limits (tokens available/capacity per minute)",
    ] + [
        f"- **{name}**: {s['available_tokens']:.1f}/{s['capacity']:.0f} (refill {s['refill_rate_per_min']:.1f}/min)"
        for name, s in rl_status.items()
    ]
    return "\n".join(lines)


@mcp.resource("cti://mitre/tactics")
async def resource_mitre_tactics() -> str:
    """All MITRE ATT&CK Enterprise tactics."""
    tactics = _mitre.get_tactics()
    if not tactics:
        return "MITRE ATT&CK Enterprise data loading. Try again in a moment, or call get_mitre_technique to trigger load."
    lines = ["# MITRE ATT&CK Enterprise Tactics\n"]
    for t in tactics:
        lines.append(f"## {t.id} — {t.name}")
        lines.append(f"*Short name*: `{t.short_name}`")
        lines.append(t.description[:300] + "...")
        lines.append("")
    return "\n".join(lines)


@mcp.resource("cti://mitre/techniques")
async def resource_mitre_techniques() -> str:
    """Summary list of all MITRE ATT&CK Enterprise techniques."""
    src = _mitre._load()
    if not src:
        return "MITRE ATT&CK data is not available."
    try:
        all_techniques = src.get_techniques(remove_revoked_deprecated=True)
        lines = ["# MITRE ATT&CK Enterprise Techniques\n",
                 "| ID | Name | Tactics | Platforms |", "|---|---|---|---|"]
        for t in all_techniques:
            parsed = _mitre._parse_technique(t)
            if parsed:
                lines.append(
                    f"| {parsed.id} | {parsed.name} | {', '.join(parsed.tactics)} "
                    f"| {', '.join(parsed.platforms[:3])} |"
                )
        return "\n".join(lines)
    except Exception as exc:
        return f"Error loading techniques: {sanitize_error(exc)}"


@mcp.resource("cti://mitre/ics/techniques")
async def resource_mitre_ics_techniques() -> str:
    """Summary list of all MITRE ATT&CK for ICS techniques."""
    src = _mitre_ics._load()
    if not src:
        return "MITRE ATT&CK for ICS data loading. Call get_mitre_ics_technique to trigger load."
    try:
        all_techniques = src.get_techniques(remove_revoked_deprecated=True)
        lines = ["# MITRE ATT&CK for ICS Techniques\n",
                 "| ID | Name | Tactics | Platforms |", "|---|---|---|---|"]
        for t in all_techniques:
            parsed = _mitre_ics._parse_technique(t)
            if parsed and parsed.id:
                lines.append(
                    f"| {parsed.id} | {parsed.name} | {', '.join(parsed.tactics)} "
                    f"| {', '.join(parsed.platforms[:3])} |"
                )
        return "\n".join(lines)
    except Exception as exc:
        return f"Error: {sanitize_error(exc)}"


@mcp.resource("cti://ics/advisories/recent")
async def resource_recent_ics_advisories() -> str:
    """20 most recent CISA ICS Security Advisories."""
    advisories = await _cisa.get_recent(limit=20)
    if not advisories:
        return "No CISA ICS advisories available. Check network connectivity."
    lines = ["# Recent CISA ICS Security Advisories\n"]
    for a in advisories:
        date_str = a.published.strftime("%Y-%m-%d") if a.published else "Unknown"
        vendors_str = ", ".join(a.affected_vendors) if a.affected_vendors else "Unknown"
        cves_str = ", ".join(a.cve_ids[:3]) if a.cve_ids else "None"
        lines.append(f"## {a.title}")
        lines.append(f"- **Date**: {date_str}")
        lines.append(f"- **Vendors**: {vendors_str}")
        lines.append(f"- **CVEs**: {cves_str}")
        if a.cvss_max:
            lines.append(f"- **CVSS Max**: {a.cvss_max}")
        if a.link:
            lines.append(f"- **Link**: {a.link}")
        lines.append("")
    return "\n".join(lines)


@mcp.resource("cti://ics/vendors")
async def resource_ics_vendors() -> str:
    """Supported OT vendor list with CPE keyword mappings."""
    lines = ["# Supported OT/ICS Vendors\n",
             "Use these vendor names with `lookup_ot_asset_cves` and `search_ics_advisories`.\n",
             "| Vendor | CPE Keywords |", "|---|---|"]
    for vendor, keywords in sorted(OT_VENDOR_CPE_MAP.items()):
        lines.append(f"| {vendor.title()} | {', '.join(keywords)} |")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — AI / LLM / AGENT SECURITY
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_atlas_technique(
    technique_id: Annotated[str, Field(description="MITRE ATLAS technique ID, e.g. AML.T0051 (Prompt Injection)")],
) -> dict:
    """
    Get MITRE ATLAS technique details for AI/ML/LLM-specific attacks.
    ATLAS covers threats unique to AI systems not in ATT&CK Enterprise.
    No API key required — uses locally cached YAML data.

    Common IDs:
    - AML.T0051: LLM Prompt Injection
    - AML.T0054: LLM Jailbreak
    - AML.T0020: Poison Training Data
    - AML.T0044: Full ML Model Access
    - AML.T0037: Data from Information Repositories
    - AML.T0018: Backdoor ML Model
    - AML.T0043: Craft Adversarial Data
    """
    technique_id = technique_id.strip().upper()
    if not technique_id.startswith("AML."):
        return {"error": "ATLAS technique IDs use the 'AML.Txxxx' format (e.g. AML.T0051). "
                         "For ATT&CK Enterprise use get_mitre_technique. "
                         "For ATT&CK ICS use get_mitre_ics_technique."}

    result = _atlas.get_technique(technique_id)
    if not result:
        return {"error": f"ATLAS technique '{technique_id}' not found. "
                         f"Search with search_atlas_techniques to find valid IDs."}
    audit_tool_call("get_atlas_technique", result_count=1)
    return result.model_dump(mode="json")


@mcp.tool()
async def search_atlas_techniques(
    query: Annotated[str, Field(description="Search term for MITRE ATLAS AI/ML attack techniques")],
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search MITRE ATLAS techniques covering AI/ML/LLM attack methods.
    Returns techniques relevant to AI Agent security, model attacks, and LLM exploitation.
    No API key required.

    Examples:
    - query="prompt injection"
    - query="jailbreak"
    - query="model extraction"
    - query="poisoning"
    - query="adversarial"
    - query="membership inference"
    - query="agent"
    """
    try:
        query = validate_query_string(query)
    except ValidationError as exc:
        return {"error": str(exc)}

    with AuditTimer("search_atlas_techniques") as t:
        results = _atlas.search_techniques(query, limit=limit)
        t.finish(result_count=len(results))
        return {
            "count": len(results),
            "techniques": [
                {
                    "id": t.id,
                    "name": t.name,
                    "tactics": t.tactics,
                    "platforms": t.platforms,
                    "is_subtechnique": t.is_subtechnique,
                    "description_snippet": t.description[:300] + "..." if len(t.description) > 300 else t.description,
                    "url": t.url,
                }
                for t in results
            ],
        }


@mcp.tool()
async def get_owasp_llm_risk(
    risk_id: Annotated[str | None, Field(description="OWASP LLM risk ID (LLM01–LLM10), or omit for full list")] = None,
) -> dict:
    """
    Get OWASP Top 10 for LLM Applications risk details.
    Covers the most critical security risks in Large Language Model deployments.
    No API key required — built-in static data (2025 edition).

    Risk IDs: LLM01 (Prompt Injection), LLM02 (Insecure Output), LLM03 (Training Poisoning),
    LLM04 (Model DoS), LLM05 (Supply Chain), LLM06 (Info Disclosure),
    LLM07 (Insecure Plugin), LLM08 (Excessive Agency), LLM09 (Overreliance), LLM10 (Model Theft)
    """
    if risk_id:
        risk_id_upper = risk_id.strip().upper()
        match = next((r for r in OWASP_LLM_TOP10 if r["id"] == risk_id_upper), None)
        if not match:
            return {"error": f"'{risk_id}' not found. Valid IDs: LLM01–LLM10"}
        audit_tool_call("get_owasp_llm_risk", result_count=1)
        return match
    else:
        audit_tool_call("get_owasp_llm_risk", result_count=len(OWASP_LLM_TOP10))
        return {
            "count": len(OWASP_LLM_TOP10),
            "risks": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "description_snippet": r["description"][:200] + "...",
                    "impact_summary": r["impact"],
                    "url": r["url"],
                }
                for r in OWASP_LLM_TOP10
            ],
        }


@mcp.tool()
async def lookup_ai_framework_cves(
    framework: Annotated[str, Field(description="AI/LLM framework name (e.g. 'langchain', 'pytorch', 'huggingface', 'ollama')")],
    severity: Annotated[str | None, Field(description="Severity filter: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    limit: Annotated[int, Field(description="Max results (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Search for CVEs affecting AI/LLM frameworks and infrastructure.
    Critical for securing AI Agent development stacks and model serving infrastructure.
    No API key required.

    Supported frameworks: langchain, openai, pytorch, tensorflow, huggingface,
    ollama, llamacpp, autogpt, crewai, mlflow, ray, triton, onnx, anthropic,
    cohere, vllm, gradio, streamlit, faiss, chromadb

    Examples:
    - framework="langchain", severity="CRITICAL"      ← LangChain RCE/injection CVEs
    - framework="ollama"                              ← Local LLM server vulnerabilities
    - framework="huggingface", severity="HIGH"        ← HuggingFace model CVEs
    - framework="gradio"                              ← Gradio web UI CVEs
    """
    fw_lower = framework.lower().strip()
    keywords = AI_FRAMEWORK_CVE_MAP.get(fw_lower)

    if not keywords:
        # Partial match
        for key, kws in AI_FRAMEWORK_CVE_MAP.items():
            if fw_lower in key or key in fw_lower:
                keywords = kws
                fw_lower = key
                break

    if not keywords:
        available = sorted(AI_FRAMEWORK_CVE_MAP.keys())
        return {
            "error": f"Framework '{framework}' not in AI framework map.",
            "supported_frameworks": available,
        }

    with AuditTimer("lookup_ai_framework_cves") as t:
        results = await _cve.search_cves(
            keyword=keywords[0], severity=severity, results_per_page=limit
        )
        t.finish(result_count=len(results))
        return {
            "framework": fw_lower,
            "search_keyword": keywords[0],
            "severity_filter": severity,
            "count": len(results),
            "cves": [
                {
                    "id": r.cve_id,
                    "severity": r.highest_severity.value,
                    "cvss_score": r.highest_cvss_score,
                    "description": r.description[:300] + "..." if len(r.description) > 300 else r.description,
                    "published": r.published.isoformat() if r.published else None,
                }
                for r in results
            ],
        }


@mcp.tool()
async def analyze_ai_agent_risk(
    agent_framework: Annotated[str, Field(description="Agent framework (e.g. 'langchain', 'crewai', 'autogpt', 'custom')")],
    capabilities: Annotated[str, Field(
        description="Comma-separated list of agent capabilities (e.g. 'web_search,code_execution,file_access,email')"
    )],
) -> dict:
    """
    Analyze the threat surface and OWASP/ATLAS risks for an AI Agent configuration.
    Provides a structured risk assessment based on declared capabilities.
    No API key required — built-in rule-based analysis.

    Example: agent_framework="langchain", capabilities="web_search,code_execution,file_access"
    """
    cap_list = [c.strip().lower() for c in capabilities.split(",") if c.strip()]

    # Risk mapping: capability → risks
    HIGH_RISK_CAPS = {
        "code_execution":   ["LLM01", "LLM07", "LLM08"],
        "file_access":      ["LLM01", "LLM06", "LLM08"],
        "shell":            ["LLM01", "LLM07", "LLM08"],
        "database":         ["LLM01", "LLM06", "LLM08"],
        "email":            ["LLM01", "LLM08"],
        "web_search":       ["LLM01", "LLM02"],
        "api_calls":        ["LLM07", "LLM08"],
        "memory":           ["LLM06"],
        "multi_agent":      ["LLM01", "LLM08"],
        "tool_use":         ["LLM07", "LLM08"],
        "browser":          ["LLM01", "LLM02"],
    }

    ATLAS_CAP_MAP = {
        "code_execution":   ["AML.T0051", "AML.T0054"],
        "web_search":       ["AML.T0051"],
        "file_access":      ["AML.T0037"],
        "multi_agent":      ["AML.T0051"],
        "memory":           ["AML.T0037", "AML.T0024"],
    }

    # Collect triggered risks
    owasp_risks: set[str] = set()
    atlas_techniques: set[str] = set()
    for cap in cap_list:
        owasp_risks.update(HIGH_RISK_CAPS.get(cap, []))
        atlas_techniques.update(ATLAS_CAP_MAP.get(cap, []))

    # Look up OWASP detail
    triggered_owasp = [
        {"id": r["id"], "name": r["name"], "impact": r["impact"],
         "mitigations": r["mitigations"]}
        for r in OWASP_LLM_TOP10 if r["id"] in owasp_risks
    ]

    # Determine overall risk level
    if any(c in cap_list for c in ["code_execution", "shell"]):
        overall_risk = "CRITICAL"
    elif any(c in cap_list for c in ["file_access", "database", "email"]):
        overall_risk = "HIGH"
    elif any(c in cap_list for c in ["web_search", "api_calls", "multi_agent"]):
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    audit_tool_call("analyze_ai_agent_risk", extra={"framework": agent_framework, "risk": overall_risk})
    return {
        "agent_framework": agent_framework,
        "declared_capabilities": cap_list,
        "overall_risk_level": overall_risk,
        "owasp_risks_triggered": triggered_owasp,
        "atlas_technique_ids": sorted(atlas_techniques),
        "key_recommendations": [
            "Apply principle of least privilege: only grant capabilities the agent actually needs",
            "Add human-in-the-loop checkpoints for irreversible or high-impact actions",
            "Sanitize all external content before injecting into LLM context",
            "Monitor and rate-limit LLM API calls per session",
            "Validate and sandbox all tool/plugin outputs before trusting",
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCES — AI / LLM SECURITY
# ══════════════════════════════════════════════════════════════════════════════

@mcp.resource("cti://ai/atlas/techniques")
async def resource_atlas_techniques() -> str:
    """All MITRE ATLAS AI/ML/LLM attack techniques."""
    techniques = _atlas.get_all_techniques()
    if not techniques:
        return "MITRE ATLAS data loading. Call get_atlas_technique to trigger load."
    lines = [
        "# MITRE ATLAS AI/LLM Attack Techniques\n",
        "| ID | Name | Tactics | Sub? |",
        "|---|---|---|---|",
    ]
    for t in sorted(techniques, key=lambda x: x.id):
        lines.append(
            f"| [{t.id}]({t.url}) | {t.name} | {', '.join(t.tactics)} "
            f"| {'Yes' if t.is_subtechnique else 'No'} |"
        )
    return "\n".join(lines)


@mcp.resource("cti://ai/owasp-llm-top10")
async def resource_owasp_llm() -> str:
    """OWASP Top 10 for LLM Applications (2025 edition)."""
    lines = [
        "# OWASP Top 10 for LLM Applications (2025)\n",
        "Reference: https://genai.owasp.org/\n",
    ]
    for r in OWASP_LLM_TOP10:
        lines.append(f"## {r['id']}: {r['name']}")
        lines.append(f"**Impact**: {r['impact']}")
        lines.append(f"\n{r['description']}\n")
        lines.append("**Mitigations**:")
        for m in r["mitigations"]:
            lines.append(f"- {m}")
        if r.get("atlas_techniques"):
            lines.append(f"\n**Related ATLAS**: {', '.join(r['atlas_techniques'])}")
        lines.append(f"\n🔗 {r['url']}\n")
    return "\n".join(lines)


@mcp.resource("cti://ai/frameworks")
async def resource_ai_frameworks() -> str:
    """Supported AI/LLM framework list for CVE lookups."""
    lines = [
        "# Supported AI/LLM Frameworks for CVE Lookup\n",
        "Use these names with `lookup_ai_framework_cves`.\n",
        "| Framework | Search Keywords |",
        "|---|---|",
    ]
    for fw, keywords in sorted(AI_FRAMEWORK_CVE_MAP.items()):
        lines.append(f"| {fw} | {', '.join(keywords)} |")
    return "\n".join(lines)



# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — VENDOR SECURITY ADVISORIES
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_recent_vendor_advisories(
    vendor: Annotated[str | None, Field(
        description=(
            "Vendor name to filter by (e.g. 'microsoft', 'siemens', 'cisco', 'sap', "
            "'oracle', 'rockwell', 'ge', 'schneider', 'abb', 'honeywell', "
            "'openai', 'anthropic', 'google'). "
            "Omit for all vendors."
        )
    )] = None,
    category: Annotated[str | None, Field(
        description="Filter by category: 'it', 'ot' (industrial), or 'ai'. Omit for all."
    )] = None,
    limit: Annotated[int, Field(description="Max results (1-50)", ge=1, le=50)] = 10,
) -> dict:
    """
    Get the most recent security advisories from major IT, OT, and AI vendors.
    Aggregates official RSS/Atom feeds (Microsoft MSRC, Siemens ProductCERT, Cisco PSIRT,
    SAP Security Notes, Oracle CPU) and NVD CVE data for vendors without public feeds
    (GE, Rockwell, Schneider, OpenAI, Anthropic).
    No API key required.

    Examples:
    - vendor="microsoft"          ← Latest Microsoft MSRC advisories (Patch Tuesday)
    - vendor="siemens"            ← Siemens ProductCERT OT/ICS advisories
    - vendor="cisco"              ← Cisco PSIRT advisories
    - category="ot", limit=20    ← All recent OT/ICS vendor advisories
    - category="ai"               ← OpenAI/Anthropic/Google security bulletins
    """
    if vendor:
        try:
            vendor = validate_query_string(vendor, "vendor")
        except ValidationError as exc:
            return {"error": str(exc)}

        vendor_lower = vendor.lower().strip()
        if vendor_lower not in VENDOR_REGISTRY:
            # Partial match check
            matches = [k for k in VENDOR_REGISTRY if vendor_lower in k or k in vendor_lower]
            if not matches:
                return {
                    "error": f"Vendor '{vendor}' not found.",
                    "supported_vendors": sorted(VENDOR_REGISTRY.keys()),
                }

    with AuditTimer("get_recent_vendor_advisories") as t:
        advisories = await _vendor_adv.get_recent(vendor=vendor, category=category, limit=limit)
        t.finish(result_count=len(advisories))

    return {
        "vendor_filter": vendor,
        "category_filter": category,
        "count": len(advisories),
        "advisories": [
            {
                "vendor": a.vendor_display,
                "title": a.title,
                "advisory_id": a.advisory_id,
                "published": a.published.isoformat() if a.published else None,
                "severity": a.severity,
                "cve_ids": a.cve_ids[:10],
                "summary": a.summary,
                "url": a.url,
                "source": a.source,
            }
            for a in advisories
        ],
    }


@mcp.tool()
async def search_vendor_advisories(
    keyword: Annotated[str | None, Field(
        description="Search term matched against advisory title and summary"
    )] = None,
    vendor: Annotated[str | None, Field(
        description="Vendor name filter (e.g. 'microsoft', 'siemens', 'cisco')"
    )] = None,
    cve_id: Annotated[str | None, Field(
        description="CVE ID to find in vendor advisories (e.g. CVE-2024-21413)"
    )] = None,
    category: Annotated[str | None, Field(
        description="Filter by 'it', 'ot', or 'ai'"
    )] = None,
    limit: Annotated[int, Field(description="Max results (1-50)", ge=1, le=50)] = 20,
) -> dict:
    """
    Search security advisories across major vendors by keyword or CVE ID.
    Covers Microsoft, Siemens, Cisco, SAP, Oracle, GE, Rockwell, Schneider,
    OpenAI, Anthropic, Google, ABB, Honeywell.
    No API key required.

    Examples:
    - keyword="remote code execution", category="ot"  ← RCE in ICS/OT products
    - vendor="microsoft", keyword="zero day"          ← Microsoft zero-days
    - cve_id="CVE-2024-21413"                         ← Find which vendors mention this CVE
    - keyword="critical", category="ai"               ← Critical AI/LLM security issues
    - vendor="cisco", keyword="IOS"                   ← Cisco IOS advisories
    """
    if not keyword and not vendor and not cve_id:
        return {"error": "Provide at least one of: keyword, vendor, cve_id"}

    try:
        if keyword:
            keyword = validate_query_string(keyword, "keyword")
        if vendor:
            vendor = validate_query_string(vendor, "vendor")
        if cve_id:
            cve_id = validate_cve_id(cve_id)
    except ValidationError as exc:
        return {"error": str(exc)}

    with AuditTimer("search_vendor_advisories") as t:
        advisories = await _vendor_adv.search(
            vendor=vendor,
            keyword=keyword,
            cve_id=cve_id,
            category=category,
            limit=limit,
        )
        t.finish(result_count=len(advisories))

    return {
        "keyword": keyword,
        "vendor_filter": vendor,
        "cve_filter": cve_id,
        "category_filter": category,
        "count": len(advisories),
        "advisories": [
            {
                "vendor": a.vendor_display,
                "title": a.title,
                "advisory_id": a.advisory_id,
                "published": a.published.isoformat() if a.published else None,
                "severity": a.severity,
                "cve_ids": a.cve_ids[:10],
                "summary": a.summary,
                "url": a.url,
                "source": a.source,
            }
            for a in advisories
        ],
    }


@mcp.resource("cti://vendors/advisory-sources")
async def resource_vendor_advisory_sources() -> str:
    """Supported vendors for security advisory queries, with category and feed info."""
    vendors = _vendor_adv.list_vendors()
    lines = [
        "# Supported Vendor Security Advisory Sources\n",
        "Use these vendor names with `get_recent_vendor_advisories` and `search_vendor_advisories`.\n",
        "| Vendor | Category | Feed Type | Description |",
        "|---|---|---|---|",
    ]
    for v in vendors:
        feed_type = "RSS/Atom ✅" if v["has_rss"] else "NVD CVE 🔍"
        lines.append(f"| {v['display_name']} (`{v['name']}`) | {v['category'].upper()} | {feed_type} | {v['description']} |")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — CROSS-INTELLIGENCE CORRELATION & RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def correlate_threat(
    input_value: Annotated[str, Field(
        description="CVE ID (e.g. 'CVE-2024-3400'), MITRE technique ID (e.g. 'T1059'), or IOC value"
    )],
    input_type: Annotated[str, Field(
        description="Type of input: 'cve', 'technique', or IOC type ('ip', 'domain', 'url', 'hash')"
    )] = "cve",
) -> dict:
    """
    Cross-source threat intelligence correlation.

    Given a single indicator, automatically fans out to ALL relevant data sources
    in parallel and assembles a unified intelligence picture with composite risk scoring.

    For CVE inputs: NVD → EPSS → CISA KEV → CWE-to-ATT&CK bridge → MITRE techniques
    → D3FEND defenses → Vendor Advisories → OTX pulses → Composite Risk Score.

    For technique inputs: MITRE details → D3FEND countermeasures → OTX pulses.

    For IOC inputs: OTX context + pulse search → threat scoring.

    Examples:
    - input_value="CVE-2024-3400", input_type="cve"
    - input_value="T1059", input_type="technique"
    - input_value="185.220.101.45", input_type="ip"
    """
    input_type_lower = input_type.lower().strip()

    with AuditTimer("correlate_threat", input_type=input_type_lower) as t:
        try:
            if input_type_lower == "cve":
                input_value = validate_cve_id(input_value)
                result = await _correlator.correlate_cve(input_value)
            elif input_type_lower == "technique":
                input_value = validate_technique_id(input_value)
                result = await _correlator.correlate_technique(input_value)
            elif input_type_lower in ("ip", "domain", "url", "hash"):
                input_value = validate_ioc(input_value, input_type_lower)
                result = await _correlator.correlate_ioc(input_value, input_type_lower)
            else:
                return {"error": f"Unsupported input_type '{input_type}'. Use 'cve', 'technique', 'ip', 'domain', 'url', or 'hash'."}

            t.finish(sources=len(result.sources_consulted))
            return result.model_dump(mode="json")
        except ValidationError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            logger.error("correlate_threat failed: %s", exc)
            return {"error": sanitize_error(exc)}


@mcp.tool()
async def get_risk_card(
    cve_id: Annotated[str, Field(description="CVE ID to generate a risk card for (e.g. 'CVE-2024-3400')")],
) -> dict:
    """
    Generate a composite risk scorecard for a CVE.

    Combines CVSS base score (25%), EPSS exploitation probability (30%),
    CISA KEV active exploitation status (20%), vendor advisory urgency (10%),
    and OTX threat intelligence interest (15%) into a single 0-100 risk score
    with actionable patch prioritization recommendation.

    This goes beyond raw CVSS to provide real-world risk-based prioritization.
    """
    try:
        cve_id = validate_cve_id(cve_id)
    except ValidationError as exc:
        return {"error": str(exc)}

    with AuditTimer("get_risk_card") as t:
        cve_data, epss_data, kev_catalog = await asyncio.gather(
            _cve.lookup_cve(cve_id),
            _intel.get_epss(cve_id),
            _intel.get_cisa_kev(),
        )

        cvss_base = cve_data.highest_cvss_score if cve_data else None
        epss_val = epss_data.epss if epss_data else None

        in_kev = False
        kev_due = None
        if kev_catalog:
            kev_entry = kev_catalog.get(cve_id)
            if kev_entry:
                in_kev = True

        # Check vendor advisories
        vendor_results = await _vendor_adv.search(cve_id=cve_id, limit=5)
        vendor_count = len(vendor_results)
        newest_age = None
        if vendor_results:
            from datetime import timezone as _tz
            now = datetime.now(tz=_tz.utc)
            for adv in vendor_results:
                if adv.published:
                    pub = adv.published if adv.published.tzinfo else adv.published.replace(tzinfo=_tz.utc)
                    age = (now - pub).total_seconds() / 86400
                    if newest_age is None or age < newest_age:
                        newest_age = age

        # Check OTX
        otx_count = 0
        if _otx.enabled:
            try:
                pulses = await _otx.search_pulses(cve_id, limit=10)
                otx_count = len(pulses)
            except Exception:
                pass

        score = compute_risk_score(
            cvss_base=cvss_base,
            epss_score=epss_val,
            in_kev=in_kev,
            kev_due_date=kev_due,
            vendor_advisory_count=vendor_count,
            newest_advisory_age_days=newest_age,
            otx_pulse_count=otx_count,
        )

        t.finish(score=score.total_score, rating=score.rating)

        return {
            "cve_id": cve_id,
            "risk_score": score.model_dump(mode="json"),
            "inputs": {
                "cvss_base": cvss_base,
                "epss_score": epss_val,
                "in_kev": in_kev,
                "vendor_advisory_count": vendor_count,
                "otx_pulse_count": otx_count,
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — BATCH OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def batch_lookup_iocs(
    indicators: Annotated[list[dict], Field(
        description=(
            "List of IOC objects, each with 'value' and 'type' keys. "
            "Example: [{'value': '8.8.8.8', 'type': 'ip'}, {'value': 'evil.com', 'type': 'domain'}]. "
            "Max 20 indicators per batch."
        )
    )],
) -> dict:
    """
    Batch IOC triage — look up multiple indicators in parallel.
    Ideal for SOC alert queues where a single SIEM event may contain many IOCs.
    Returns aggregated verdicts for all indicators with controlled concurrency.
    Max 20 indicators per batch.
    """
    if not indicators or not isinstance(indicators, list):
        return {"error": "indicators must be a non-empty list of {value, type} objects"}
    if len(indicators) > 20:
        return {"error": "Maximum 20 indicators per batch"}

    with AuditTimer("batch_lookup_iocs") as t:
        sem = asyncio.Semaphore(5)

        async def _lookup_one(item: dict) -> dict:
            val = item.get("value", "")
            typ = item.get("type", "")
            if not val or not typ:
                return {"value": val, "type": typ, "error": "Missing value or type"}
            async with sem:
                try:
                    return await lookup_ioc(indicator=val, ioc_type=typ)
                except Exception as exc:
                    return {"value": val, "type": typ, "error": str(exc)}

        results = await asyncio.gather(*[_lookup_one(i) for i in indicators])
        t.finish(count=len(results))

        malicious = sum(1 for r in results if r.get("verdict") == "malicious")
        suspicious = sum(1 for r in results if r.get("verdict") == "suspicious")

        return {
            "total": len(results),
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "results": list(results),
        }


@mcp.tool()
async def batch_enrich_cves(
    cve_ids: Annotated[list[str], Field(
        description="List of CVE IDs to enrich. Example: ['CVE-2024-3400', 'CVE-2021-44228']. Max 20."
    )],
) -> dict:
    """
    Batch CVE enrichment — enrich multiple CVEs with EPSS scores, CISA KEV status,
    and composite risk scores in parallel.
    Ideal for vulnerability scan triage where a scanner outputs dozens of CVEs.
    Results are sorted by risk score (highest first) for immediate prioritization.
    Max 20 CVEs per batch.
    """
    if not cve_ids or not isinstance(cve_ids, list):
        return {"error": "cve_ids must be a non-empty list of CVE ID strings"}
    if len(cve_ids) > 20:
        return {"error": "Maximum 20 CVEs per batch"}

    with AuditTimer("batch_enrich_cves") as t:
        sem = asyncio.Semaphore(5)

        async def _enrich_one(cve_id: str) -> dict:
            async with sem:
                try:
                    cve_id = validate_cve_id(cve_id)
                    card = await get_risk_card(cve_id=cve_id)
                    return card
                except Exception as exc:
                    return {"cve_id": cve_id, "error": str(exc)}

        results = await asyncio.gather(*[_enrich_one(c) for c in cve_ids])
        results_list = list(results)

        results_list.sort(
            key=lambda r: r.get("risk_score", {}).get("total_score", 0),
            reverse=True,
        )

        t.finish(count=len(results_list))

        return {
            "total": len(results_list),
            "results": results_list,
        }


@mcp.tool()
async def batch_vendor_check(
    cve_ids: Annotated[list[str], Field(
        description="List of CVE IDs to check against vendor advisories. Max 20."
    )],
    vendor: Annotated[str | None, Field(
        description="Optional vendor name to filter advisories (e.g. 'microsoft', 'cisco')"
    )] = None,
) -> dict:
    """
    Check which CVEs have published vendor security advisories.
    Useful for patch management: quickly identify which CVEs from a vulnerability scan
    already have official vendor guidance available.
    Max 20 CVEs per batch.
    """
    if not cve_ids or not isinstance(cve_ids, list):
        return {"error": "cve_ids must be a non-empty list of CVE ID strings"}
    if len(cve_ids) > 20:
        return {"error": "Maximum 20 CVEs per batch"}

    with AuditTimer("batch_vendor_check") as t:
        results: list[dict] = []
        with_advisory = 0

        for cve_id in cve_ids:
            try:
                cve_id = validate_cve_id(cve_id)
            except ValidationError:
                results.append({"cve_id": cve_id, "error": "Invalid CVE ID format"})
                continue

            advisories = await _vendor_adv.search(
                vendor=vendor, cve_id=cve_id, limit=5
            )
            has_adv = len(advisories) > 0
            if has_adv:
                with_advisory += 1

            results.append({
                "cve_id": cve_id,
                "has_vendor_advisory": has_adv,
                "advisory_count": len(advisories),
                "advisories": [
                    {
                        "vendor": a.vendor_display,
                        "title": a.title,
                        "severity": a.severity,
                        "url": a.url,
                    }
                    for a in advisories
                ],
            })

        t.finish(count=len(results), with_advisory=with_advisory)

        return {
            "total": len(results),
            "with_advisory": with_advisory,
            "without_advisory": len(results) - with_advisory,
            "vendor_filter": vendor,
            "results": results,
        }


# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — THREAT LANDSCAPE
# ══════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_threat_landscape(
    category: Annotated[str | None, Field(
        description="Filter by domain: 'it', 'ot', 'ai', or omit for all. Controls which vendor advisories are included."
    )] = None,
    limit: Annotated[int, Field(description="Max items per section (1-20)", ge=1, le=20)] = 10,
) -> dict:
    """
    Aggregated threat landscape snapshot — what's happening right now.

    Combines data from multiple sources to produce a situational awareness briefing:
    - Recent high-severity CVEs (from NVD)
    - New CISA KEV additions (confirmed in-the-wild exploitation)
    - Latest vendor security advisories (filtered by category if specified)
    - Recent ICS/OT advisories from CISA (if category is 'ot' or unfiltered)

    Ideal for morning security standup, executive briefings, or threat dashboard feeds.
    """
    from datetime import timezone as _tz

    with AuditTimer("get_threat_landscape", category=category) as t:
        tasks = {
            "cves": _cve.search_cves(severity="CRITICAL", results_per_page=min(limit, 10)),
            "kev": _intel.get_cisa_kev(),
            "vendor": _vendor_adv.get_recent(category=category, limit=limit),
        }

        include_ics = category is None or category.lower() == "ot"
        if include_ics:
            tasks["ics"] = _cisa.get_recent(limit=limit)

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        results_map = dict(zip(tasks.keys(), gathered))

        landscape: dict = {
            "category_filter": category,
            "top_cves": [],
            "recent_kev_additions": [],
            "vendor_advisories": [],
            "ics_advisories": [],
        }

        # Top CVEs
        cves = results_map.get("cves")
        if cves and not isinstance(cves, Exception):
            for cve in cves[:limit]:
                landscape["top_cves"].append({
                    "cve_id": cve.cve_id,
                    "severity": cve.highest_severity.value if cve.highest_severity else None,
                    "cvss": cve.highest_cvss_score,
                    "description": cve.description[:200],
                    "published": cve.published.isoformat() if cve.published else None,
                })

        # KEV additions (most recent by date_added)
        kev_catalog = results_map.get("kev")
        if kev_catalog and not isinstance(kev_catalog, Exception):
            sorted_kev = sorted(
                kev_catalog.values(),
                key=lambda k: k.date_added,
                reverse=True,
            )
            for entry in sorted_kev[:limit]:
                landscape["recent_kev_additions"].append({
                    "cve_id": entry.cve_id,
                    "vendor": entry.vendor_project,
                    "product": entry.product,
                    "vulnerability_name": entry.vulnerability_name,
                    "date_added": entry.date_added,
                    "ransomware_use": entry.known_ransomware_campaign_use,
                })

        # Vendor advisories
        vendor = results_map.get("vendor")
        if vendor and not isinstance(vendor, Exception):
            for adv in vendor[:limit]:
                landscape["vendor_advisories"].append({
                    "vendor": adv.vendor_display,
                    "title": adv.title,
                    "severity": adv.severity,
                    "published": adv.published.isoformat() if adv.published else None,
                    "url": adv.url,
                    "cve_ids": adv.cve_ids[:5],
                })

        # ICS advisories
        ics = results_map.get("ics")
        if ics and not isinstance(ics, Exception):
            for a in ics[:limit]:
                landscape["ics_advisories"].append(a.model_dump(mode="json"))

        total_items = sum(len(v) for v in landscape.values() if isinstance(v, list))
        t.finish(total_items=total_items)

        landscape["total_items"] = total_items
        return landscape


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE — CWE-to-ATT&CK Mapping
# ══════════════════════════════════════════════════════════════════════════════

@mcp.resource("cti://cwe-attack-map")
async def resource_cwe_attack_map() -> str:
    """CWE-to-ATT&CK technique mapping used by the correlation engine."""
    lines = [
        "# CWE → MITRE ATT&CK Technique Mapping\n",
        "Used by `correlate_threat` to automatically derive ATT&CK techniques from CVE weakness types.\n",
        "| CWE ID | ATT&CK Techniques |",
        "|---|---|",
    ]
    for cwe, techs in sorted(CWE_TO_ATTACK_MAP.items()):
        lines.append(f"| {cwe} | {', '.join(techs)} |")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# PROMPTS
# ══════════════════════════════════════════════════════════════════════════════

@mcp.prompt()
async def analyze_threat_actor(
    actor_name: Annotated[str, Field(description="Name of the threat actor or APT group (e.g. Lazarus, Sandworm)")]
) -> list[PromptMessage]:
    """
    Template for deeply analyzing a threat actor.
    Instructs the LLM to query MITRE for the actor, gather their known techniques, and map out defenses.
    """
    prompt_text = (
        f"I need a comprehensive threat profile for the actor known as '{actor_name}'.\n\n"
        f"Please follow these steps:\n"
        f"1. Use `search_threat_actors` to find their exact group ID and aliases.\n"
        f"2. Summarize their typical targets, motivations, and associated malware.\n"
        f"3. Highlight their most common ATT&CK techniques.\n"
        f"4. For their key techniques, use `get_mitre_d3fend_countermeasures` to suggest 3-5 prioritized defensive actions we must take immediately."
    )
    return [
        PromptMessage(
            role="user",
            content=TextContent(type="text", text=prompt_text)
        )
    ]


@mcp.prompt()
async def investigate_asset_supply_chain(
    asset_name: Annotated[str, Field(description="Name of the software or system components (e.g. apache_tomcat, log4j-core)")]
) -> list[PromptMessage]:
    """
    Template for supply chain security analysis on a specific IT/OT/AI asset or package.
    """
    prompt_text = (
        f"We are auditing our usage of the asset/package '{asset_name}'.\n\n"
        f"Please perform a supply chain security check:\n"
        f"1. Use `search_cves` to find general high/critical IT or OT vulnerabilities.\n"
        f"2. Use `lookup_osv_package` to check the OSV open-source ecosystem database for specific package exploits.\n"
        f"3. For the most critical CVE found (if any), use `is_cve_known_exploited` and `get_epss_score` to determine if we are facing active threat in the wild.\n"
        f"4. Output a clear risk matrix and upgrade recommendation."
    )
    return [
        PromptMessage(
            role="user",
            content=TextContent(type="text", text=prompt_text)
        )
    ]


# ── IT Security Operations ────────────────────────────────────────────────────

@mcp.prompt()
async def it_incident_triage(
    indicator: Annotated[str, Field(description="Suspicious indicator: IP address, domain, file hash, or URL flagged in IT environment")],
    system_context: Annotated[str, Field(description="Brief description of the affected IT system (e.g. 'Windows Server 2019 used as internal file share')")] = "corporate IT system",
) -> list[PromptMessage]:
    """
    IT Security Operations Center (SOC) — Rapid triage of a suspicious indicator.
    Chains IOC lookup → active exploit check → MITRE ATT&CK mapping → recommended response actions.
    Ideal for: SOC analysts investigating endpoint/network alerts.
    """
    prompt_text = (
        f"**IT SOC Incident Triage**\n\n"
        f"A suspicious indicator has been flagged in our {system_context}:\n"
        f"Indicator: `{indicator}`\n\n"
        f"Please perform a complete triage:\n"
        f"1. Use `lookup_ioc` to check reputation across threat intelligence sources (VirusTotal, OTX).\n"
        f"2. If the indicator has associated CVEs, use `lookup_cve` on the top 2-3 to get CVSS scores and patch status.\n"
        f"3. Use `search_mitre_techniques` to identify the ATT&CK techniques most likely associated with this type of indicator.\n"
        f"4. For associated techniques, use `get_mitre_d3fend_countermeasures` to suggest detections we should enable immediately.\n"
        f"5. Output a structured triage report with: Verdict / Confidence / Associated techniques / Immediate actions (within 1h) / Short-term hardening actions (within 1 week)."
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


@mcp.prompt()
async def it_patch_prioritization(
    product: Annotated[str, Field(description="Software product or vendor to assess (e.g. 'Microsoft Exchange', 'Cisco IOS', 'Apache HTTP Server')")],
) -> list[PromptMessage]:
    """
    IT Patch Management — Prioritize which CVEs to patch first for a given product.
    Uses CVSS, EPSS exploit probability, CISA KEV status, and vendor advisories.
    Ideal for: Patch Tuesday planning, IT vulnerability management teams.
    """
    prompt_text = (
        f"**Patch Prioritization Report for: {product}**\n\n"
        f"Our security team needs to prioritize patching for `{product}`.\n\n"
        f"Please run the following analysis:\n"
        f"1. Use `search_vendor_advisories` with the relevant vendor name to get the latest official security advisories.\n"
        f"2. Use `search_cves` to find HIGH and CRITICAL CVEs for this product.\n"
        f"3. For each CVE found (up to 5), use `is_cve_known_exploited` to check CISA KEV status and `get_epss_score` for exploitation probability.\n"
        f"4. Rank the CVEs by: (1) KEV status, (2) EPSS score, (3) CVSS base score.\n"
        f"5. Output a patch priority table:\n"
        f"   | CVE | CVSS | EPSS | In KEV | Recommendation | Patch Deadline |\n"
        f"   with clear SLA recommendations: P1=24h (KEV), P2=7d (EPSS>50%), P3=30d (others)."
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


# ── OT / ICS Industrial Security ─────────────────────────────────────────────

@mcp.prompt()
async def ot_plant_security_assessment(
    plant_type: Annotated[str, Field(description="Type of industrial facility (e.g. 'power plant', 'water treatment', 'oil refinery', 'manufacturing')")],
    vendor_list: Annotated[str, Field(description="Key OT vendors or products in use, comma-separated (e.g. 'Siemens S7, Rockwell ControlLogix, Honeywell DCS')")],
) -> list[PromptMessage]:
    """
    OT Plant Security Assessment — Full security posture review for an industrial facility.
    Chains ICS advisories → OT CVEs → MITRE ATT&CK for ICS techniques → risk summary.
    Ideal for: OT security engineers, plant managers, compliance teams (IEC 62443).
    """
    prompt_text = (
        f"**OT Plant Security Assessment**\n\n"
        f"Facility type: {plant_type}\n"
        f"OT vendors/products in use: {vendor_list}\n\n"
        f"Please perform a systematic security assessment:\n"
        f"1. Use `get_recent_vendor_advisories` for each vendor mentioned (e.g. siemens, rockwell, honeywell) to pull the latest security bulletins.\n"
        f"2. Use `lookup_ot_asset_cves` for each vendor/product combination to find unpatched CVEs (severity=HIGH or CRITICAL).\n"
        f"3. Use `get_recent_ics_advisories` to check CISA's latest ICS-CERT advisories relevant to this facility type.\n"
        f"4. Use `search_mitre_ics_techniques` to identify the top 5 ATT&CK for ICS techniques targeting this sector.\n"
        f"5. Produce an IEC 62443-aligned risk report:\n"
        f"   - Unresolved CVEs with patch urgency\n"
        f"   - Active threat actors targeting this sector (with MITRE ATT&CK techniques)\n"
        f"   - Top 5 immediate security controls to implement\n"
        f"   - Recommended monitoring and detection signatures"
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


@mcp.prompt()
async def ot_ics_compromise_investigation(
    anomaly_description: Annotated[str, Field(description="Description of the suspicious behavior or anomaly observed in the OT/ICS network (e.g. 'unexpected Modbus writes to PLC outputs at 2AM')")],
    affected_system: Annotated[str, Field(description="Affected OT system or device (e.g. 'Siemens S7-300 PLC', 'Schneider Electric SCADA HMI')")] = "ICS/OT device",
) -> list[PromptMessage]:
    """
    OT ICS Compromise Investigation — Threat hunt and incident response for OT anomalies.
    Maps anomaly → ATT&CK for ICS techniques → threat actor attribution → response playbook.
    Ideal for: OT incident response teams, industrial SOC analysts.
    """
    prompt_text = (
        f"**OT/ICS Compromise Investigation**\n\n"
        f"Anomaly detected on: {affected_system}\n"
        f"Description: {anomaly_description}\n\n"
        f"Please run an OT threat investigation:\n"
        f"1. Use `search_mitre_ics_techniques` to identify which ATT&CK for ICS techniques match this anomaly pattern.\n"
        f"2. For the top matching techniques, look up the full technique detail with `get_mitre_ics_technique`.\n"
        f"3. Use `search_cves` with the affected device/vendor as keyword to find recently disclosed vulnerabilities that could explain the anomaly.\n"
        f"4. Use `search_ics_advisories` to see if CISA has issued recent advisories for this vendor/system.\n"
        f"5. Produce an ICS incident response playbook:\n"
        f"   - Probable attack technique (with MITRE ICS TTP IDs)\n"
        f"   - Potential threat actors known to use these TTPs\n"
        f"   - Immediate containment steps (OT-safe, network-aware)\n"
        f"   - Evidence to collect for forensic analysis\n"
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


# ── AI / LLM Security ─────────────────────────────────────────────────────────

@mcp.prompt()
async def ai_llm_deployment_security_review(
    system_name: Annotated[str, Field(description="Name of the AI/LLM system or application being reviewed (e.g. 'Customer service chatbot powered by GPT-4')")],
    framework: Annotated[str, Field(description="AI framework or stack in use (e.g. 'langchain', 'openai', 'ollama', 'autogpt')")] = "langchain",
    capabilities: Annotated[str, Field(description="Capabilities the AI agent has, comma-separated (e.g. 'web_search,code_execution,database_access,email')")] = "web_search,api_calls",
) -> list[PromptMessage]:
    """
    AI/LLM Deployment Security Review — Comprehensive security assessment before going live.
    Covers OWASP LLM Top 10, MITRE ATLAS techniques, framework CVEs, and hardening recommendations.
    Ideal for: AI product teams, security architects reviewing LLM applications for production.
    """
    prompt_text = (
        f"**AI/LLM Deployment Security Review**\n\n"
        f"System: {system_name}\n"
        f"Framework: {framework}\n"
        f"Capabilities granted to AI: {capabilities}\n\n"
        f"Please perform a pre-deployment security review:\n"
        f"1. Use `analyze_ai_agent_risk` with the provided framework and capabilities to get an automated risk score.\n"
        f"2. Use `lookup_ai_framework_cves` for the framework to find known CVEs we need to patch before launch.\n"
        f"3. Use `get_owasp_llm_risk` for each triggered OWASP risk (from step 1) to get detailed mitigation steps.\n"
        f"4. Use `search_atlas_techniques` with keywords matching the capabilities (e.g. 'prompt injection', 'data exfiltration') to find MITRE ATLAS techniques to defend against.\n"
        f"5. Produce a Go/No-Go security report:\n"
        f"   - Overall risk rating (LOW/MEDIUM/HIGH/CRITICAL)\n"
        f"   - OWASP LLM Top 10 risks that apply\n"
        f"   - MITRE ATLAS adversarial techniques to mitigate\n"
        f"   - Must-fix items before launch (blocking)\n"
        f"   - Recommended security controls and monitoring\n"
        f"   - Compliance considerations (GDPR, AI Act, SOC2)"
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


@mcp.prompt()
async def ai_vendor_security_posture(
    ai_vendor: Annotated[str, Field(description="AI vendor or model provider to investigate (e.g. 'openai', 'anthropic', 'google', 'meta')")],
) -> list[PromptMessage]:
    """
    AI Vendor Security Posture Review — Assess the security track record of an AI/LLM vendor.
    Checks their CVE history, published advisories, and disclosed vulnerabilities.
    Ideal for: CISO risk assessments, AI procurement security due diligence.
    """
    prompt_text = (
        f"**AI Vendor Security Posture Review: {ai_vendor}**\n\n"
        f"Our organization is evaluating or already uses AI services from `{ai_vendor}`.\n"
        f"Please perform a security due diligence assessment:\n\n"
        f"1. Use `get_recent_vendor_advisories` with vendor='{ai_vendor}' to pull their recent security bulletins.\n"
        f"2. Use `lookup_ai_framework_cves` if the vendor maps to an AI framework to find CVEs in their software stack.\n"
        f"3. Use `search_atlas_techniques` with 'model extraction' and 'data poisoning' to understand attack vectors targeting this type of AI system.\n"
        f"4. Use `get_owasp_llm_risk` to pull the full OWASP LLM Top 10 relevant to consuming this vendor's API.\n"
        f"5. Produce a vendor security scorecard:\n"
        f"   - CVE count and severity breakdown (last 12 months)\n"
        f"   - Time-to-patch track record\n"
        f"   - Key security risks in using their service\n"
        f"   - Recommended contractual security requirements\n"
        f"   - Suggested monitoring and contingency plans (vendor lock-in / outage risk)"
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


# ── Cross-Intelligence Workflow Prompts ───────────────────────────────────────

@mcp.prompt()
async def vulnerability_triage_briefing(
    cve_list: Annotated[str, Field(
        description="Comma-separated CVE IDs from a vulnerability scan (e.g. 'CVE-2024-3400, CVE-2021-44228, CVE-2023-4966')"
    )],
) -> list[PromptMessage]:
    """
    Vulnerability Triage Briefing — batch risk scoring and prioritized patch plan.
    Takes a list of CVEs from a vulnerability scan and produces a business-ready patch
    prioritization report using composite risk scoring (CVSS + EPSS + KEV + vendor advisories).
    Ideal for: vulnerability management teams after scan results, Patch Tuesday planning.
    """
    prompt_text = (
        f"**Vulnerability Triage Briefing**\n\n"
        f"Our vulnerability scanner has flagged the following CVEs:\n"
        f"`{cve_list}`\n\n"
        f"Please produce a prioritized patch plan:\n"
        f"1. Use `batch_enrich_cves` with the full list of CVE IDs to get composite risk scores for all CVEs at once.\n"
        f"2. For the top 3 highest-risk CVEs, use `correlate_threat` with input_type='cve' to get full cross-source intelligence (MITRE techniques, D3FEND defenses, vendor advisories).\n"
        f"3. Use `batch_vendor_check` to identify which CVEs already have vendor patch guidance available.\n"
        f"4. Produce a structured triage report:\n"
        f"   - **Priority 1 (Patch Immediately)**: CVEs with risk score >= 80 or in CISA KEV\n"
        f"   - **Priority 2 (Patch within 7 days)**: CVEs with risk score 50-79\n"
        f"   - **Priority 3 (Patch within 30 days)**: CVEs with risk score < 50\n"
        f"   - For each CVE: risk score, CVSS, EPSS probability, KEV status, vendor advisory link\n"
        f"   - Compensating controls from D3FEND for any CVEs that cannot be patched immediately\n"
        f"5. Close with an executive summary: total CVEs, critical count, percentage with active exploitation, and estimated remediation effort."
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


@mcp.prompt()
async def morning_threat_briefing(
    category: Annotated[str, Field(
        description="Focus area: 'it' for IT security, 'ot' for industrial/ICS, 'ai' for AI/LLM security, or 'all' for everything"
    )] = "all",
) -> list[PromptMessage]:
    """
    Morning Threat Briefing — daily situational awareness for security leadership.
    Generates an executive-ready daily threat intelligence digest covering new vulnerabilities,
    active exploitations, vendor advisories, and ICS alerts.
    Ideal for: CISOs, SOC leads, daily standup meetings.
    """
    cat_filter = None if category == "all" else category
    cat_label = f" ({category.upper()})" if category != "all" else ""
    cat_arg = f' with category="{cat_filter}"' if cat_filter else ""

    prompt_text = (
        f"**Daily Threat Intelligence Briefing{cat_label}**\n\n"
        f"Please compile today's threat landscape briefing:\n\n"
        f"1. Use `get_threat_landscape`{cat_arg} to pull the current threat landscape snapshot.\n"
        f"2. From the results, identify the top 3 most critical items that require immediate attention.\n"
        f"3. For any CISA KEV additions from the last 7 days, use `get_risk_card` to assess their real-world risk.\n"
        f"4. For the highest-risk vendor advisory, use `correlate_threat` to map it to MITRE techniques and D3FEND countermeasures.\n"
        f"5. Produce a concise executive briefing (suitable for a 5-minute standup):\n"
        f"   - **Headline**: One-sentence summary of the most critical development\n"
        f"   - **New Active Threats**: KEV additions with risk scores\n"
        f"   - **Vendor Patches**: Key advisories requiring action\n"
        f"   - **Action Items**: Specific steps for the security team today\n"
        f"   - **Trend Watch**: Any emerging patterns or campaigns to monitor"
    )
    return [PromptMessage(role="user", content=TextContent(type="text", text=prompt_text))]


# ══════════════════════════════════════════════════════════════════════════════
# SERVER ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Run the CTI MCP server (STDIO transport by default)."""
    import sys
    transport = "stdio"
    # Flexible parsing for 'http' or '--transport=http' or '--transport http'
    if "http" in sys.argv:
        transport = "http"
    for i, arg in enumerate(sys.argv):
        if arg == "--transport" and i + 1 < len(sys.argv):
            transport = sys.argv[i+1]
        if arg.startswith("--transport="):
            transport = arg.split("=", 1)[1]

    logger.info("Starting CTI MCP Server v2 (transport=%s)", transport)
    logger.info("Enabled sources: %s", config.get_enabled_sources())

    # Start background warmup thread
    warmup_thread = threading.Thread(target=_warmup, daemon=True)
    warmup_thread.start()
    if transport == "http":
        print(f"DEBUG: HTTP mode starting on {config.MCP_HTTP_HOST}:{config.MCP_HTTP_PORT}")
        
        # Bypass FastMCP DNS Rebinding Protection for Docker/Public access
        if hasattr(mcp, "settings") and hasattr(mcp.settings, "allowed_origins"):
            # Allow common internal and external access points
            mcp.settings.allowed_origins.extend([
                "http://cti-mcp:8000",
                "http://45.63.121.92",
                "http://45.63.121.92:5173",
                "*"
            ])
            print(f"DEBUG: Updated FastMCP allowed_origins: {mcp.settings.allowed_origins}")
        
        # Inject Logging Middleware and BUGS FIX for FastMCP
        # This patch fixes the "Missing session ID" error on initial GET requests
        try:
            import mcp.server.streamable_http as streamable_http
            
            # More robust monkey-patch of the class method
            old_validate_session = streamable_http.StreamableHTTP._validate_session
            
            async def patched_validate_session(self, request, send):
                # If it's a GET request (SSE initiation), we bypass the session ID check
                path = request.url.path
                if request.method == "GET" and (path == "/mcp" or path == "/sse" or path == "/"):
                    return True
                return await old_validate_session(self, request, send)
            
            streamable_http.StreamableHTTP._validate_session = patched_validate_session
            print("DEBUG: Successfully applied patch to StreamableHTTP._validate_session")
            
            from starlette.middleware.base import BaseHTTPMiddleware
            class HeaderLoggerMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request, call_next):
                    print(f"INCOMING: {request.method} {request.url.path}")
                    response = await call_next(request)
                    return response
            
            # Use getattr to safely check for the app attribute
            app = getattr(mcp, "_fastapi_app", None) or getattr(mcp, "_app", None)
            if app:
                app.add_middleware(HeaderLoggerMiddleware)
                print("DEBUG: Applied HeaderLoggerMiddleware")
        except Exception as e:
            print(f"ERROR applying patches: {e}")

        mcp.run(transport="streamable-http",
                host=config.MCP_HTTP_HOST,
                port=config.MCP_HTTP_PORT)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
