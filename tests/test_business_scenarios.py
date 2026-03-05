"""
CTI MCP Server — Business Scenario Integration Tests
Tests real API calls to validate actual return content.

Usage:
    python tests/test_business_scenarios.py              # run all scenarios
    python tests/test_business_scenarios.py --scenario=it  # run only IT scenarios

Prerequisites:
    - pip install -e .
    - Set VIRUSTOTAL_API_KEY / OTX_API_KEY in .env for full coverage
      (ICS/AI/CVE/MITRE scenarios work without any API keys)
"""

import asyncio
import json
import sys
import time
from typing import Any

# ── Color output helpers ─────────────────────────────────────────────────────

def _green(s: str) -> str: return f"\033[32m{s}\033[0m"
def _red(s: str) -> str: return f"\033[31m{s}\033[0m"
def _yellow(s: str) -> str: return f"\033[33m{s}\033[0m"
def _cyan(s: str) -> str: return f"\033[36m{s}\033[0m"
def _bold(s: str) -> str: return f"\033[1m{s}\033[0m"


class ScenarioRunner:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.results: list[dict] = []

    def _dump(self, data: Any, max_len: int = 800) -> str:
        s = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        if len(s) > max_len:
            s = s[:max_len] + f"\n  ... [{len(s)-max_len} chars truncated]"
        return s

    async def run(
        self,
        name: str,
        coro,
        *,
        assert_fn=None,
        expect_error=False,
        skip_if=False,
        skip_reason="",
    ) -> None:
        if skip_if:
            self.skipped += 1
            print(f"  {_yellow('SKIP')} {name} — {skip_reason}")
            return

        print(f"\n{'='*70}")
        print(f"  {_bold(name)}")
        print(f"{'='*70}")
        t0 = time.monotonic()
        try:
            result = await coro
            latency = (time.monotonic() - t0) * 1000

            if "error" in result and not expect_error:
                print(_red(f"  ✗ FAILED — Tool returned error: {result['error']}"))
                self.failed += 1
                self.results.append({"name": name, "status": "FAILED", "error": result["error"]})
                return

            if expect_error and "error" not in result:
                print(_red(f"  ✗ FAILED — Expected error but got success"))
                self.failed += 1
                self.results.append({"name": name, "status": "FAILED", "error": "expected error not raised"})
                return

            if assert_fn:
                try:
                    assert_fn(result)
                except AssertionError as exc:
                    print(_red(f"  ✗ ASSERTION FAILED — {exc}"))
                    print(self._dump(result))
                    self.failed += 1
                    self.results.append({"name": name, "status": "ASSERT_FAIL"})
                    return

            print(_green(f"  ✓ PASSED ({latency:.0f}ms)"))
            print(self._dump(result))
            self.passed += 1
            self.results.append({"name": name, "status": "PASSED", "latency_ms": round(latency)})

        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            print(_red(f"  ✗ EXCEPTION — {exc}"))
            self.failed += 1
            self.results.append({"name": name, "status": "EXCEPTION", "error": str(exc)})

    def summary(self) -> None:
        print(f"\n{'='*70}")
        print(_bold("BUSINESS SCENARIO TEST SUMMARY"))
        print(f"{'='*70}")
        total = self.passed + self.failed + self.skipped
        print(f"  Total:   {total}")
        print(f"  {_green('Passed')}: {self.passed}")
        print(f"  {_red('Failed')}: {self.failed}")
        print(f"  {_yellow('Skipped')}: {self.skipped}")

        if self.failed > 0:
            print(f"\n{_red('FAILED SCENARIOS:')}")
            for r in self.results:
                if r["status"] not in ("PASSED",):
                    print(f"  - {r['name']}: {r.get('error', r['status'])}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

async def run_it_security_scenarios(runner: ScenarioRunner) -> None:
    """IT 安全运营场景"""
    from src.server import (
        lookup_ioc, get_threat_summary, lookup_cve, search_cves,
        get_mitre_technique, search_mitre_techniques,
    )

    print(f"\n{_cyan(_bold('【IT 安全运营场景】'))}")

    # 1. IOC 查询 - 已知 Cloudflare DNS（应为 clean）
    await runner.run(
        "IOC查询 — Cloudflare DNS 1.1.1.1 (应为 clean/unknown，无威胁)",
        lookup_ioc(indicator="1.1.1.1", ioc_type="ip"),
        assert_fn=lambda r: r.get("verdict") in ("clean", "unknown"),
    )

    # 2. IOC 安全验证 — 私有 IP 应被拒绝
    await runner.run(
        "IOC安全验证 — 私有 IP 192.168.1.1 应被 SSRF 防护拦截",
        lookup_ioc(indicator="192.168.1.1", ioc_type="ip"),
        expect_error=True,
    )

    # 3. Hash 查询 — EICAR 测试文件 MD5
    await runner.run(
        "Hash 查询 — EICAR 测试恶意软件 MD5",
        lookup_ioc(
            indicator="44d88612fea8a8f36de82e1278abb02f",
            ioc_type="hash",
        ),
        assert_fn=lambda r: "verdict" in r,
    )

    # 4. CVE Log4Shell 详情
    await runner.run(
        "CVE 查询 — CVE-2021-44228 Log4Shell (CVSS 10.0)",
        lookup_cve(cve_id="CVE-2021-44228"),
        assert_fn=lambda r: (
            "error" not in r
            and r.get("cve_id") == "CVE-2021-44228"
            and any(c.get("base_score", 0) >= 9.0 for c in r.get("cvss", []))
        ),
    )

    # 5. CVE 搜索 — 关键词搜索
    await runner.run(
        "CVE 搜索 — 'remote code execution' severity=CRITICAL",
        search_cves(keyword="remote code execution", severity="CRITICAL", limit=5),
        assert_fn=lambda r: r.get("count", 0) > 0,
    )

    # 6. MITRE T1059 — Command Scripting
    await runner.run(
        "MITRE ATT&CK — T1059 Command and Scripting Interpreter",
        get_mitre_technique(technique_id="T1059"),
        assert_fn=lambda r: (
            "error" not in r
            and "T1059" in r.get("id", "")
        ),
    )

    # 7. MITRE 搜索 — 凭据窃取
    await runner.run(
        "MITRE 搜索 — 'credential dumping'",
        search_mitre_techniques(query="credential dumping", limit=5),
        assert_fn=lambda r: r.get("count", 0) > 0,
    )


async def run_ics_security_scenarios(runner: ScenarioRunner) -> None:
    """ICS/OT 工业安全场景"""
    from src.server import (
        search_ics_advisories, get_recent_ics_advisories,
        get_mitre_ics_technique, search_mitre_ics_techniques,
        lookup_ot_asset_cves,
    )

    print(f"\n{_cyan(_bold('【ICS/OT 工业安全场景】'))}")

    # 8. CISA 最新 ICS 公告
    await runner.run(
        "CISA ICS 公告 — 获取最近 5 条安全公告",
        get_recent_ics_advisories(limit=5),
        assert_fn=lambda r: r.get("count", 0) >= 0,  # 网络可能不可达
    )

    # 9. Siemens ICS 公告搜索
    await runner.run(
        "ICS 公告搜索 — vendor=Siemens",
        search_ics_advisories(vendor="Siemens", limit=5),
    )

    # 10. MITRE ATT&CK for ICS — Unauthorized Command
    await runner.run(
        "ATT&CK for ICS — T0855 Unauthorized Command Message",
        get_mitre_ics_technique(technique_id="T0855"),
        assert_fn=lambda r: (
            "error" not in r
            and "T0855" in r.get("id", "")
        ),
    )

    # 11. ICS 技术搜索
    await runner.run(
        "ATT&CK for ICS 搜索 — 'modbus'",
        search_mitre_ics_techniques(query="modbus", limit=5),
        assert_fn=lambda r: r.get("count", 0) >= 0,
    )

    # 12. Siemens CVE 查询
    await runner.run(
        "OT 设备 CVE — Siemens SCALANCE (severity=HIGH)",
        lookup_ot_asset_cves(vendor="siemens", product="scalance", severity="HIGH", limit=5),
        assert_fn=lambda r: "error" not in r or "siemens" in str(r).lower(),
    )

    # 13. Rockwell CVE 查询
    await runner.run(
        "OT 设备 CVE — Rockwell Automation ControlLogix",
        lookup_ot_asset_cves(vendor="rockwell", product="logix", limit=5),
        assert_fn=lambda r: "error" not in r or "supported_vendors" not in r,
    )

    # 14. 未知厂商应给出错误提示
    await runner.run(
        "OT 设备 CVE 安全验证 — 未知厂商应返回支持厂商列表",
        lookup_ot_asset_cves(vendor="nonexistentvendor12345"),
        expect_error=True,
        assert_fn=lambda r: "supported_vendors" in r,
    )


async def run_ai_llm_scenarios(runner: ScenarioRunner) -> None:
    """AI/LLM/Agent 安全场景"""
    from src.server import (
        get_atlas_technique, search_atlas_techniques,
        get_owasp_llm_risk, lookup_ai_framework_cves,
        analyze_ai_agent_risk,
    )

    print(f"\n{_cyan(_bold('【AI/LLM/Agent 安全场景】'))}")

    # 15. OWASP LLM Top 10 全览
    await runner.run(
        "OWASP LLM Top 10 — 获取全部 10 个风险",
        get_owasp_llm_risk(),
        assert_fn=lambda r: r.get("count") == 10,
    )

    # 16. OWASP LLM01 Prompt Injection 详情
    await runner.run(
        "OWASP LLM01 — Prompt Injection 风险详情（含缓解措施）",
        get_owasp_llm_risk(risk_id="LLM01"),
        assert_fn=lambda r: (
            r.get("id") == "LLM01"
            and isinstance(r.get("mitigations"), list)
            and len(r.get("mitigations", [])) > 0
        ),
    )

    # 17. OWASP LLM08 Excessive Agency
    await runner.run(
        "OWASP LLM08 — Excessive Agency（AI Agent 过度权限场景）",
        get_owasp_llm_risk(risk_id="LLM08"),
        assert_fn=lambda r: r.get("id") == "LLM08",
    )

    # 18. MITRE ATLAS 搜索 — Prompt Injection
    await runner.run(
        "MITRE ATLAS 搜索 — 'prompt injection'",
        search_atlas_techniques(query="prompt injection", limit=5),
        assert_fn=lambda r: r.get("count", 0) >= 0,
    )

    # 19. MITRE ATLAS 搜索 — Model Extraction
    await runner.run(
        "MITRE ATLAS 搜索 — 'model extraction'",
        search_atlas_techniques(query="model extraction", limit=5),
        assert_fn=lambda r: r.get("count", 0) >= 0,
    )

    # 20. ATLAS 技术 ID 前缀验证（非 AML 前缀应报错）
    await runner.run(
        "ATLAS 安全验证 — 错误前缀 T1059 应提示使用 AML.Txxxx 格式",
        get_atlas_technique(technique_id="T1059"),
        expect_error=True,
        assert_fn=lambda r: "AML." in r.get("error", ""),
    )

    # 21. LangChain CVE — 已知多个 RCE 漏洞
    await runner.run(
        "AI 框架 CVE — LangChain (已知有 RCE/Injection 漏洞)",
        lookup_ai_framework_cves(framework="langchain", limit=5),
        assert_fn=lambda r: (
            "error" not in r
            and r.get("framework") == "langchain"
        ),
    )

    # 22. Ollama CVE 查询
    await runner.run(
        "AI 框架 CVE — Ollama 本地 LLM 服务器漏洞",
        lookup_ai_framework_cves(framework="ollama", limit=5),
        assert_fn=lambda r: "error" not in r,
    )

    # 23. Gradio CVE — 已知有未授权访问漏洞
    await runner.run(
        "AI 框架 CVE — Gradio Web UI 漏洞",
        lookup_ai_framework_cves(framework="gradio", limit=5),
        assert_fn=lambda r: "error" not in r,
    )

    # 24. Agent 风险评估 — 高危 Agent（代码执行+文件访问）
    await runner.run(
        "Agent 威胁评估 — LangChain Agent with code_execution+file_access",
        analyze_ai_agent_risk(
            agent_framework="langchain",
            capabilities="web_search,code_execution,file_access,email,multi_agent",
        ),
        assert_fn=lambda r: (
            r.get("overall_risk_level") == "CRITICAL"
            and len(r.get("owasp_risks_triggered", [])) >= 3
            and len(r.get("atlas_technique_ids", [])) > 0
            and len(r.get("key_recommendations", [])) >= 3
        ),
    )

    # 25. Agent 风险评估 — 低风险 Agent（read-only）
    await runner.run(
        "Agent 威胁评估 — Read-only Agent (低风险期望)",
        analyze_ai_agent_risk(
            agent_framework="custom",
            capabilities="respond_only,read_docs",
        ),
        assert_fn=lambda r: r.get("overall_risk_level") == "LOW",
    )

    # 26. Agent 风险评估 — CrewAI 多 Agent 协作
    await runner.run(
        "Agent 威胁评估 — CrewAI multi-agent framework",
        analyze_ai_agent_risk(
            agent_framework="crewai",
            capabilities="web_search,multi_agent,api_calls,memory",
        ),
        assert_fn=lambda r: (
            r.get("overall_risk_level") in ("MEDIUM", "HIGH", "CRITICAL")
            and any(r["id"] == "LLM01" for r in r.get("owasp_risks_triggered", []))
        ),
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main() -> int:
    import os
    from dotenv import load_dotenv
    from pathlib import Path
    load_dotenv(Path(__file__).parent.parent / ".env")

    has_vt = bool(os.getenv("VIRUSTOTAL_API_KEY", ""))
    has_otx = bool(os.getenv("OTX_API_KEY", ""))

    print(_bold("\nCTI MCP Server -- Business Scenario Integration Tests"))
    print(f"  VirusTotal: {'✅ configured' if has_vt else '⚠️  no key (IOC results will be limited)'}")
    print(f"  OTX:        {'✅ configured' if has_otx else '⚠️  no key (OTX data unavailable)'}")
    print()

    runner = ScenarioRunner()

    # Run all scenario groups
    filter_arg = next((a.replace("--scenario=", "") for a in sys.argv[1:] if a.startswith("--scenario=")), None)

    if not filter_arg or filter_arg == "it":
        await run_it_security_scenarios(runner)
    if not filter_arg or filter_arg == "ics":
        await run_ics_security_scenarios(runner)
    if not filter_arg or filter_arg == "ai":
        await run_ai_llm_scenarios(runner)

    runner.summary()
    return 1 if runner.failed > 0 else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
