"""
MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) connector.
Covers AI/ML/LLM-specific attack techniques not present in ATT&CK Enterprise.

Data source: https://github.com/mitre-atlas/atlas-data (v4.7+, Generative AI update)
No API key required — downloads YAML from GitHub, caches locally.

Key technique categories:
 - Prompt Injection (AML.T0051)
 - LLM Jailbreak (AML.T0054)
 - Model Inversion / Extraction
 - Training Data Poisoning
 - Adversarial Examples
 - Membership Inference
"""

import logging
from pathlib import Path
from typing import Any

import httpx

from ..config import config
from ..models import MitreTactic, MitreTechnique

logger = logging.getLogger(__name__)

_CACHE_DIR = Path(config.MITRE_CACHE_DIR)
_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_ATLAS_YAML_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
)
_ATLAS_CACHE_FILE = _CACHE_DIR / "ATLAS.yaml"


class MitreAtlasConnector:
    """
    MITRE ATLAS AI Threat Matrix connector.
    Parses the ATLAS.yaml distributed file (YAML, not STIX).
    Technique IDs use the AML.Txxxx namespace.
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] | None = None

    def _load(self) -> dict[str, Any] | None:
        if self._data is not None:
            return self._data

        try:
            import yaml  # type: ignore
        except ImportError:
            logger.error("pyyaml not installed. Run: pip install pyyaml")
            return None

        try:
            if not _ATLAS_CACHE_FILE.exists():
                logger.info("Downloading MITRE ATLAS YAML (first run)...")
                resp = httpx.get(_ATLAS_YAML_URL, timeout=60, follow_redirects=True)
                resp.raise_for_status()
                _ATLAS_CACHE_FILE.write_bytes(resp.content)
                logger.info("ATLAS YAML downloaded (%d bytes)", len(resp.content))

            with open(_ATLAS_CACHE_FILE, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f)
            logger.info("MITRE ATLAS data loaded (version: %s)",
                        self._data.get("id", "unknown"))
            return self._data
        except Exception as exc:
            logger.error("Failed to load ATLAS data: %s", exc)
            return None

    def _get_matrix(self) -> dict[str, Any] | None:
        data = self._load()
        if not data:
            return None
        matrices = data.get("matrices", [])
        return matrices[0] if matrices else None

    def get_tactics(self) -> list[MitreTactic]:
        """Return all ATLAS tactics."""
        matrix = self._get_matrix()
        if not matrix:
            return []

        result = []
        for tactic in matrix.get("tactics", []):
            tactic_id = tactic.get("id", "")
            result.append(MitreTactic(
                id=tactic_id,
                name=tactic.get("name", ""),
                short_name=tactic.get("id", "").lower().replace(".", "-"),
                description=tactic.get("description", "")[:500],
                url=f"https://atlas.mitre.org/tactics/{tactic_id}",
            ))
        return result

    def get_technique(self, technique_id: str) -> MitreTechnique | None:
        """Get an ATLAS technique by ID (e.g., AML.T0051)."""
        matrix = self._get_matrix()
        if not matrix:
            return None

        for technique in matrix.get("techniques", []):
            t_id = technique.get("id", "")
            if t_id.upper() == technique_id.upper():
                return self._parse_technique(technique)
            # Check subtechniques
            for sub in technique.get("subtechniques", []):
                if sub.get("id", "").upper() == technique_id.upper():
                    parsed = self._parse_technique(sub)
                    if parsed:
                        parsed.parent_id = t_id
                        parsed.is_subtechnique = True
                    return parsed
        return None

    def search_techniques(self, query: str, limit: int = 10) -> list[MitreTechnique]:
        """Full-text search across ATLAS technique names and descriptions."""
        matrix = self._get_matrix()
        if not matrix:
            return []

        query_lower = query.lower()
        results: list[MitreTechnique] = []

        for technique in matrix.get("techniques", []):
            if self._matches(technique, query_lower):
                parsed = self._parse_technique(technique)
                if parsed:
                    results.append(parsed)
            # Also search subtechniques
            for sub in technique.get("subtechniques", []):
                if self._matches(sub, query_lower):
                    parsed = self._parse_technique(sub)
                    if parsed:
                        parsed.parent_id = technique.get("id")
                        parsed.is_subtechnique = True
                        results.append(parsed)
            if len(results) >= limit:
                break

        return results[:limit]

    def get_techniques_by_tactic(self, tactic_id: str) -> list[MitreTechnique]:
        """Return techniques associated with a given tactic ID."""
        matrix = self._get_matrix()
        if not matrix:
            return []

        results = []
        tactic_id_upper = tactic_id.upper()
        for technique in matrix.get("techniques", []):
            tactic_refs = [t.get("id", "").upper() for t in technique.get("tactics", [])]
            if tactic_id_upper in tactic_refs:
                parsed = self._parse_technique(technique)
                if parsed:
                    results.append(parsed)
        return results

    def get_all_techniques(self) -> list[MitreTechnique]:
        """Return all ATLAS techniques (including subtechniques)."""
        matrix = self._get_matrix()
        if not matrix:
            return []

        results = []
        for technique in matrix.get("techniques", []):
            parsed = self._parse_technique(technique)
            if parsed:
                results.append(parsed)
            for sub in technique.get("subtechniques", []):
                parsed_sub = self._parse_technique(sub)
                if parsed_sub:
                    parsed_sub.parent_id = technique.get("id")
                    parsed_sub.is_subtechnique = True
                    results.append(parsed_sub)
        return results

    def _matches(self, technique: dict, query_lower: str) -> bool:
        name = technique.get("name", "").lower()
        desc = technique.get("description", "").lower()
        return query_lower in name or query_lower in desc

    def _parse_technique(self, t: dict[str, Any]) -> MitreTechnique | None:
        try:
            t_id = t.get("id", "")
            tactics = [tac.get("id", "") for tac in t.get("tactics", [])]
            platforms = t.get("platforms", [])
            # ATLAS techniques may use different field names
            if isinstance(platforms, str):
                platforms = [platforms]

            return MitreTechnique(
                id=t_id,
                name=t.get("name", ""),
                description=t.get("description", ""),
                platforms=platforms if platforms else ["AI/ML Systems"],
                tactics=tactics,
                is_subtechnique="." in t_id and len(t_id.split(".")) > 2,
                detection=t.get("detection", ""),
                url=f"https://atlas.mitre.org/techniques/{t_id}",
                data_sources=t.get("data_sources", []),
            )
        except Exception as exc:
            logger.error("ATLAS _parse_technique failed: %s", exc)
            return None


# ── OWASP LLM Top 10 Static Data ─────────────────────────────────────────────
# Source: OWASP Top 10 for LLM Applications 2025
# https://genai.owasp.org/

OWASP_LLM_TOP10: list[dict] = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": (
            "Prompt injection occurs when an attacker manipulates LLM behavior through "
            "crafted inputs, causing the model to execute unintended instructions. "
            "Includes direct injection (user-supplied prompts) and indirect injection "
            "(malicious content in external sources like documents, web pages)."
        ),
        "impact": "Data exfiltration, unauthorized actions, security bypass, LLM acting as attack relay",
        "mitigations": [
            "Privilege separation between LLM and tool execution",
            "Input/output validation and sanitization",
            "Prompt guardrails and content filtering",
            "Least privilege for LLM actions",
        ],
        "atlas_techniques": ["AML.T0051", "AML.T0054"],
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    {
        "id": "LLM02",
        "name": "Insecure Output Handling",
        "description": (
            "Insufficient validation, sanitization, or handling of LLM outputs before "
            "downstream use. Can lead to XSS, CSRF, SSRF, privilege escalation, or "
            "remote code execution when LLM output is directly interpreted by other systems."
        ),
        "impact": "XSS, RCE, SSRF via unsanitized LLM output in agents or applications",
        "mitigations": [
            "Treat LLM output as untrusted user input",
            "Output encoding appropriate to context (HTML, SQL, shell)",
            "Strict output schema validation",
        ],
        "atlas_techniques": [],
        "url": "https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/",
    },
    {
        "id": "LLM03",
        "name": "Training Data Poisoning",
        "description": (
            "Manipulation of pre-training or fine-tuning data to introduce vulnerabilities, "
            "backdoors, or biases. Poisoned models may behave adversarially on specific triggers "
            "while appearing normal otherwise."
        ),
        "impact": "Backdoored model, biased outputs, attacker-controlled model behaviors",
        "mitigations": [
            "Data provenance and integrity verification",
            "Anomaly detection in training datasets",
            "Model behavioral testing post-training",
        ],
        "atlas_techniques": ["AML.T0020"],
        "url": "https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/",
    },
    {
        "id": "LLM04",
        "name": "Model Denial of Service",
        "description": (
            "Attackers craft inputs that consume excessive LLM resources, causing degradation "
            "or unavailability. Includes recursive context extensions, repetitive complex queries, "
            "and context window overflow attacks."
        ),
        "impact": "API cost explosion, service unavailability, degraded response quality",
        "mitigations": [
            "Input length limits and rate limiting",
            "Cost monitoring and alerts",
            "Context window management",
        ],
        "atlas_techniques": [],
        "url": "https://genai.owasp.org/llmrisk/llm04-model-denial-of-service/",
    },
    {
        "id": "LLM05",
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Risks from the AI/LLM supply chain: pre-trained models, fine-tuned models, "
            "plugins, datasets, and infrastructure. Includes compromised model registries, "
            "malicious LoRA adapters, and dependency confusion attacks."
        ),
        "impact": "Backdoored models, data exfiltration, supply chain compromise",
        "mitigations": [
            "Verify model hashes and signatures",
            "Use trusted model sources and artifact registries",
            "Dependency scanning for ML packages",
        ],
        "atlas_techniques": ["AML.T0018"],
        "url": "https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/",
    },
    {
        "id": "LLM06",
        "name": "Sensitive Information Disclosure",
        "description": (
            "LLMs inadvertently reveal confidential data from training corpus or injected context. "
            "Includes personal data memorization, verbatim training data recitation, "
            "system prompt extraction, and context leakage in multi-tenant deployments."
        ),
        "impact": "PII/IP leakage, system prompt theft, training data reconstruction",
        "mitigations": [
            "Differential privacy in training",
            "PII scrubbing from training data",
            "System prompt confidentiality enforcement",
            "Output filtering for sensitive patterns",
        ],
        "atlas_techniques": ["AML.T0037", "AML.T0024"],
        "url": "https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/",
    },
    {
        "id": "LLM07",
        "name": "Insecure Plugin Design",
        "description": (
            "LLM plugins/tools with inadequate access control, input validation, "
            "or following principle of least privilege. Enables privilege escalation, "
            "unauthorized external access, or SSRF via compromised plugin execution."
        ),
        "impact": "Privilege escalation, data access, SSRF, unauthorized action execution",
        "mitigations": [
            "Plugin authentication and authorization",
            "Input validation on plugin parameters",
            "Sandbox plugin execution",
            "Explicit user confirmation for high-impact actions",
        ],
        "atlas_techniques": [],
        "url": "https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/",
    },
    {
        "id": "LLM08",
        "name": "Excessive Agency",
        "description": (
            "LLM-based systems granted excessive permissions or autonomy, enabling "
            "unintended actions with real-world impact. Common in agentic frameworks "
            "where LLMs orchestrate tools, APIs, or other agents without sufficient guardrails."
        ),
        "impact": "Unintended data deletion, unauthorized transactions, cascading agent failures",
        "mitigations": [
            "Principle of least privilege for LLM tool access",
            "Human-in-the-loop for irreversible actions",
            "Action scope limitations",
            "Explicit permission scoping per session",
        ],
        "atlas_techniques": [],
        "url": "https://genai.owasp.org/llmrisk/llm08-excessive-agency/",
    },
    {
        "id": "LLM09",
        "name": "Overreliance",
        "description": (
            "Users or systems excessively trusting LLM outputs without appropriate verification, "
            "leading to security and safety failures. LLMs confidently produce incorrect, "
            "outdated, or hallucinated information that is acted upon without scrutiny."
        ),
        "impact": "Security decisions based on hallucinated CVEs, incorrect mitigations applied",
        "mitigations": [
            "Retrieval-augmented generation (RAG) for factual grounding",
            "Output confidence scoring and uncertainty disclosure",
            "Human review checkpoints for decisions",
        ],
        "atlas_techniques": [],
        "url": "https://genai.owasp.org/llmrisk/llm09-overreliance/",
    },
    {
        "id": "LLM10",
        "name": "Model Theft",
        "description": (
            "Unauthorized replication of proprietary LLMs via model extraction attacks. "
            "Attackers query the model systematically to create a functionally equivalent "
            "surrogate, stealing intellectual property and bypassing access controls."
        ),
        "impact": "IP theft, surrogate models used for adversarial attack development",
        "mitigations": [
            "Rate limiting on inference API",
            "Query monitoring for extraction patterns",
            "Watermarking model outputs",
        ],
        "atlas_techniques": ["AML.T0044", "AML.T0005"],
        "url": "https://genai.owasp.org/llmrisk/llm10-model-theft/",
    },
]


# ── AI Framework CVE Keyword Map ─────────────────────────────────────────────
# Maps framework aliases to NVD search keywords

AI_FRAMEWORK_CVE_MAP: dict[str, list[str]] = {
    "langchain": ["langchain"],
    "openai": ["openai", "chatgpt", "gpt-4"],
    "pytorch": ["pytorch", "torch"],
    "tensorflow": ["tensorflow", "keras"],
    "huggingface": ["huggingface", "transformers", "safetensors"],
    "ollama": ["ollama"],
    "llamacpp": ["llama.cpp", "llama-cpp"],
    "autogpt": ["autogpt", "auto-gpt"],
    "crewai": ["crewai", "crew-ai"],
    "langsmith": ["langsmith"],
    "mlflow": ["mlflow"],
    "ray": ["ray[serve]", "ray serve"],
    "triton": ["triton inference"],
    "onnx": ["onnxruntime", "onnx"],
    "anthropic": ["anthropic", "claude"],
    "cohere": ["cohere"],
    "vllm": ["vllm"],
    "gradio": ["gradio"],
    "streamlit": ["streamlit"],
    "faiss": ["faiss"],
    "chromadb": ["chromadb", "chroma"],
}
