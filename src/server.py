"""
CTI MCP Server — Enhanced main entrypoint.
v2: ICS/OT tools, input validation, audit logging, concurrent queries, circuit breakers.
"""

import asyncio
import logging
import threading
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
from .models import (
    DataSourceStatus,
    IOCResult,
    IOCType,
    ServiceStatus,
)
from .ratelimit import get_rate_limit_status
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
        f"   - Notification requirements (CISA, sector ISAC, regulators)"
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


# ══════════════════════════════════════════════════════════════════════════════
# SERVER ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Run the CTI MCP server (STDIO transport by default)."""
    import sys
    transport = "stdio"
    for arg in sys.argv[1:]:
        if arg.startswith("--transport="):
            transport = arg.split("=", 1)[1]

    logger.info("Starting CTI MCP Server v2 (transport=%s)", transport)
    logger.info("Enabled sources: %s", config.get_enabled_sources())

    # Start background warmup thread
    warmup_thread = threading.Thread(target=_warmup, daemon=True)
    warmup_thread.start()

    if transport == "http":
        logger.info("HTTP mode: %s:%d (auth=%s)",
                    config.MCP_HTTP_HOST, config.MCP_HTTP_PORT,
                    "enabled" if config.is_http_auth_enabled() else "disabled")
        
        # DEBUG: Dump FastMCP properties to find the exact route
        logger.info("====== FASTMCP DEBUG INFO ======")
        logger.info("mcp dir: %s", dir(mcp))
        if hasattr(mcp, "name"):
            logger.info("mcp name: %s", mcp.name)
        
        # Try to initialize the ASGI app to inspect routes
        try:
            if hasattr(mcp, "_fastapi_app"):
                from fastapi.routing import APIRoute
                app = mcp._fastapi_app
                for route in app.routes:
                    if hasattr(route, "path"):
                        logger.info("Found explicitly mapped route: %s methods=%s", route.path, getattr(route, "methods", []))
            elif hasattr(mcp, "auth_token"):
                pass
        except Exception as e:
            logger.error("Debug route inspection failed: %s", e)
            
        logger.info("Starting Uvicorn directly from FastMCP...")
        logger.info("=================================")

        mcp.run(transport="streamable-http",
                host=config.MCP_HTTP_HOST,
                port=config.MCP_HTTP_PORT)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
