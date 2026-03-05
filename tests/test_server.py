"""
Enhanced tests for CTI MCP Server v2.
Covers: validators, rate limiter, circuit breaker, ICS tools, and existing tools.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.models import IOCType, VTDetection, IOCResult
from src.validators import (
    ValidationError,
    validate_ip,
    validate_domain,
    validate_hash,
    validate_url,
    validate_cve_id,
    validate_technique_id,
    sanitize_error,
)


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATORS
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateIP:
    def test_valid_public_ip(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_valid_ipv6(self):
        result = validate_ip("2001:4860:4860::8888")
        assert "2001" in result

    def test_rejects_private_10(self):
        with pytest.raises(ValidationError, match="Private"):
            validate_ip("10.0.0.1")

    def test_rejects_private_192(self):
        with pytest.raises(ValidationError, match="Private"):
            validate_ip("192.168.1.1")

    def test_rejects_loopback(self):
        with pytest.raises(ValidationError, match="Private"):
            validate_ip("127.0.0.1")

    def test_rejects_link_local(self):
        with pytest.raises(ValidationError, match="Private"):
            validate_ip("169.254.1.1")

    def test_rejects_invalid_format(self):
        with pytest.raises(ValidationError, match="Invalid"):
            validate_ip("not-an-ip")

    def test_rejects_too_long(self):
        with pytest.raises(ValidationError):
            validate_ip("1" * 50)


class TestValidateDomain:
    def test_valid_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_normalizes_to_lower(self):
        assert validate_domain("EXAMPLE.COM") == "example.com"

    def test_rejects_localhost(self):
        with pytest.raises(ValidationError):
            validate_domain("localhost")

    def test_rejects_invalid(self):
        with pytest.raises(ValidationError):
            validate_domain("not valid domain!")


class TestValidateHash:
    def test_valid_md5(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        assert validate_hash(h) == h

    def test_valid_sha1(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert validate_hash(h) == h

    def test_valid_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert validate_hash(h) == h

    def test_normalizes_uppercase(self):
        h = "44D88612FEA8A8F36DE82E1278ABB02F"
        assert validate_hash(h) == h.lower()

    def test_rejects_wrong_length(self):
        with pytest.raises(ValidationError, match="length"):
            validate_hash("abc123")

    def test_rejects_non_hex(self):
        with pytest.raises(ValidationError, match="hex"):
            validate_hash("g" * 32)


class TestValidateURL:
    def test_valid_url(self):
        url = "https://example.com/path"
        assert validate_url(url) == url

    def test_rejects_file_scheme(self):
        with pytest.raises(ValidationError, match="scheme"):
            validate_url("file:///etc/passwd")

    def test_rejects_ftp(self):
        with pytest.raises(ValidationError, match="scheme"):
            validate_url("ftp://example.com")

    def test_rejects_localhost_url(self):
        with pytest.raises(ValidationError):
            validate_url("http://localhost/admin")

    def test_rejects_private_ip_url(self):
        with pytest.raises(ValidationError, match="private"):
            validate_url("http://192.168.1.1/shell")

    def test_rejects_too_long(self):
        with pytest.raises(ValidationError, match="too long"):
            validate_url("https://example.com/" + "a" * 2100)


class TestValidateCVEId:
    def test_valid_cve(self):
        assert validate_cve_id("CVE-2021-44228") == "CVE-2021-44228"

    def test_normalizes_lowercase(self):
        assert validate_cve_id("cve-2021-44228") == "CVE-2021-44228"

    def test_rejects_invalid(self):
        with pytest.raises(ValidationError):
            validate_cve_id("NOT-A-CVE")


class TestValidateTechniqueId:
    def test_valid_technique(self):
        assert validate_technique_id("T1059") == "T1059"

    def test_valid_subtechnique(self):
        assert validate_technique_id("T1059.001") == "T1059.001"

    def test_valid_ics_technique(self):
        assert validate_technique_id("T0855") == "T0855"

    def test_rejects_invalid(self):
        with pytest.raises(ValidationError):
            validate_technique_id("INVALID")


class TestSanitizeError:
    def test_redacts_api_keys(self):
        exc = Exception("Key: abcdef1234567890abcdef1234567890")
        result = sanitize_error(exc)
        assert "abcdef1234567890" not in result
        assert "[REDACTED]" in result

    def test_redacts_windows_path(self):
        exc = Exception(r"Error in C:\Users\secret\file.py")
        result = sanitize_error(exc)
        assert "secret" not in result

    def test_truncates_long_message(self):
        exc = Exception("x" * 500)
        result = sanitize_error(exc)
        assert len(result) <= 303


# ══════════════════════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ══════════════════════════════════════════════════════════════════════════════

class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_closed_state_allows_calls(self):
        from src.circuit_breaker import CircuitBreaker, CBState
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=60)
        result = await cb.call(AsyncMock(return_value="ok"))
        assert result == "ok"
        assert cb.state == CBState.CLOSED

    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self):
        from src.circuit_breaker import CircuitBreaker, CBState
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=60)
        failing = AsyncMock(side_effect=Exception("fail"))
        for _ in range(2):
            with pytest.raises(Exception):
                await cb.call(failing)
        assert cb.state == CBState.OPEN

    @pytest.mark.asyncio
    async def test_open_state_rejects_fast(self):
        from src.circuit_breaker import CircuitBreaker
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=999)
        failing = AsyncMock(side_effect=Exception("fail"))
        with pytest.raises(Exception):
            await cb.call(failing)
        with pytest.raises(RuntimeError, match="OPEN"):
            await cb.call(AsyncMock(return_value="ok"))


# ══════════════════════════════════════════════════════════════════════════════
# MCP TOOLS (original)
# ══════════════════════════════════════════════════════════════════════════════

class TestIOCResult:
    def test_verdict_malicious(self):
        vt = VTDetection(malicious=55, suspicious=5, harmless=5, undetected=7, total=72)
        result = IOCResult(indicator="1.2.3.4", ioc_type=IOCType.IP, vt=vt)
        result.sources_queried = ["virustotal"]
        result.compute_verdict()
        assert result.verdict == "malicious"

    def test_verdict_clean(self):
        vt = VTDetection(malicious=0, suspicious=0, harmless=70, undetected=5, total=75)
        result = IOCResult(indicator="8.8.8.8", ioc_type=IOCType.IP, vt=vt)
        result.compute_verdict()
        assert result.verdict == "clean"

    def test_verdict_unknown_no_data(self):
        result = IOCResult(indicator="1.1.1.1", ioc_type=IOCType.IP)
        result.compute_verdict()
        assert result.verdict == "unknown"


class TestLookupIOC:
    @pytest.mark.asyncio
    async def test_invalid_ioc_type(self):
        from src.server import lookup_ioc
        result = await lookup_ioc(indicator="1.2.3.4", ioc_type="invalid")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_rejects_private_ip(self):
        from src.server import lookup_ioc
        result = await lookup_ioc(indicator="192.168.1.1", ioc_type="ip")
        assert "error" in result
        assert "Private" in result["error"] or "private" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_rejects_localhost(self):
        from src.server import lookup_ioc
        result = await lookup_ioc(indicator="localhost", ioc_type="domain")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_lookup_no_sources(self, monkeypatch):
        monkeypatch.setattr("src.server._vt._enabled", False)
        monkeypatch.setattr("src.server._otx._enabled", False)
        from src.server import lookup_ioc
        result = await lookup_ioc(indicator="8.8.8.8", ioc_type="ip")
        assert "error" not in result
        assert result["verdict"] == "unknown"


class TestLookupCVE:
    @pytest.mark.asyncio
    async def test_invalid_cve_format(self):
        from src.server import lookup_cve
        result = await lookup_cve(cve_id="NOT-A-CVE")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_not_found(self, monkeypatch):
        monkeypatch.setattr("src.server._cve.lookup_cve", AsyncMock(return_value=None))
        from src.server import lookup_cve
        result = await lookup_cve(cve_id="CVE-9999-99999")
        assert "error" in result


class TestMitreICSTools:
    @pytest.mark.asyncio
    async def test_get_ics_technique_invalid_id(self):
        from src.server import get_mitre_ics_technique
        result = await get_mitre_ics_technique(technique_id="INVALID")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_search_ics_techniques_empty_query(self):
        from src.server import search_mitre_ics_techniques
        result = await search_mitre_ics_techniques(query="   ")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_search_ics_techniques_mocked(self, monkeypatch):
        from src.models import MitreTechnique
        monkeypatch.setattr(
            "src.server._mitre_ics.search_techniques",
            MagicMock(return_value=[
                MitreTechnique(
                    id="T0855",
                    name="Unauthorized Command Message",
                    description="Adversaries may send unauthorized commands.",
                    tactics=["impair-process-control"],
                    platforms=["Field Controller/RTU/PLC/IED"],
                )
            ]),
        )
        from src.server import search_mitre_ics_techniques
        result = await search_mitre_ics_techniques(query="command")
        assert result["count"] == 1
        assert result["techniques"][0]["id"] == "T0855"


class TestICSAdvisories:
    @pytest.mark.asyncio
    async def test_search_no_filters(self):
        from src.server import search_ics_advisories
        result = await search_ics_advisories()
        assert "error" in result

    @pytest.mark.asyncio
    async def test_lookup_ot_asset_unknown_vendor(self):
        from src.server import lookup_ot_asset_cves
        result = await lookup_ot_asset_cves(vendor="unknownvendorxyz")
        assert "error" in result
        assert "supported_vendors" in result


# ══════════════════════════════════════════════════════════════════════════════
# AI / LLM / ATLAS TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class TestOWASPLLMTool:
    @pytest.mark.asyncio
    async def test_get_all_risks(self):
        from src.server import get_owasp_llm_risk
        result = await get_owasp_llm_risk()
        assert result["count"] == 10
        ids = [r["id"] for r in result["risks"]]
        assert "LLM01" in ids
        assert "LLM08" in ids
        assert "LLM10" in ids

    @pytest.mark.asyncio
    async def test_get_specific_risk(self):
        from src.server import get_owasp_llm_risk
        result = await get_owasp_llm_risk(risk_id="LLM01")
        assert result["id"] == "LLM01"
        assert "Prompt Injection" in result["name"]
        assert "mitigations" in result
        assert isinstance(result["mitigations"], list)

    @pytest.mark.asyncio
    async def test_case_insensitive_risk_id(self):
        from src.server import get_owasp_llm_risk
        result = await get_owasp_llm_risk(risk_id="llm08")
        assert result["id"] == "LLM08"

    @pytest.mark.asyncio
    async def test_invalid_risk_id(self):
        from src.server import get_owasp_llm_risk
        result = await get_owasp_llm_risk(risk_id="LLM99")
        assert "error" in result


class TestAtlasTools:
    @pytest.mark.asyncio
    async def test_get_atlas_technique_wrong_prefix(self):
        from src.server import get_atlas_technique
        result = await get_atlas_technique(technique_id="T1059")
        assert "error" in result
        assert "AML." in result["error"]

    @pytest.mark.asyncio
    async def test_search_atlas_empty_query(self):
        from src.server import search_atlas_techniques
        result = await search_atlas_techniques(query="  ")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_search_atlas_mocked(self, monkeypatch):
        from src.models import MitreTechnique
        monkeypatch.setattr(
            "src.server._atlas.search_techniques",
            MagicMock(return_value=[
                MitreTechnique(
                    id="AML.T0051",
                    name="LLM Prompt Injection",
                    description="Adversaries craft inputs to manipulate LLM behavior.",
                    tactics=["ml-attack-staging"],
                    platforms=["AI/ML Systems"],
                )
            ]),
        )
        from src.server import search_atlas_techniques
        result = await search_atlas_techniques(query="prompt injection")
        assert result["count"] == 1
        assert result["techniques"][0]["id"] == "AML.T0051"


class TestAIAgentRisk:
    @pytest.mark.asyncio
    async def test_critical_risk_code_execution(self):
        from src.server import analyze_ai_agent_risk
        result = await analyze_ai_agent_risk(
            agent_framework="langchain",
            capabilities="web_search,code_execution,file_access"
        )
        assert result["overall_risk_level"] == "CRITICAL"
        owasp_ids = [r["id"] for r in result["owasp_risks_triggered"]]
        assert "LLM01" in owasp_ids  # Prompt injection always triggered with code_execution
        assert "LLM08" in owasp_ids  # Excessive agency
        assert len(result["atlas_technique_ids"]) > 0
        assert len(result["key_recommendations"]) >= 3

    @pytest.mark.asyncio
    async def test_medium_risk_web_only(self):
        from src.server import analyze_ai_agent_risk
        result = await analyze_ai_agent_risk(
            agent_framework="custom",
            capabilities="web_search,api_calls"
        )
        assert result["overall_risk_level"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_low_risk_no_capabilities(self):
        from src.server import analyze_ai_agent_risk
        result = await analyze_ai_agent_risk(
            agent_framework="custom",
            capabilities="respond_only"
        )
        assert result["overall_risk_level"] == "LOW"
        assert result["owasp_risks_triggered"] == []


class TestAIFrameworkCVE:
    @pytest.mark.asyncio
    async def test_unknown_framework(self):
        from src.server import lookup_ai_framework_cves
        result = await lookup_ai_framework_cves(framework="unknownframework12345")
        assert "error" in result
        assert "supported_frameworks" in result

    @pytest.mark.asyncio
    async def test_known_framework_mocked(self, monkeypatch):
        monkeypatch.setattr(
            "src.server._cve.search_cves",
            AsyncMock(return_value=[]),
        )
        from src.server import lookup_ai_framework_cves
        result = await lookup_ai_framework_cves(framework="langchain")
        assert "error" not in result
        assert result["framework"] == "langchain"
        assert "count" in result
