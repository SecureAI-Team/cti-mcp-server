"""
Configuration management for the CTI MCP Server.
Reads from environment variables / .env file.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).parent.parent / ".env")


def _get_bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes")


class Config:
    # ── API Keys ──────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

    # ── Server ────────────────────────────────────────────────
    MCP_SERVER_NAME: str = os.getenv("MCP_SERVER_NAME", "cti-mcp-server")
    MCP_HTTP_PORT: int = int(os.getenv("MCP_HTTP_PORT", "8080"))
    # Bind to 127.0.0.1 by default (safe); set 0.0.0.0 only if explicitly requested
    MCP_HTTP_HOST: str = os.getenv("MCP_HTTP_HOST", "127.0.0.1")
    # Bearer token for HTTP mode authentication (empty = no auth, dev-only)
    MCP_AUTH_TOKEN: str = os.getenv("MCP_AUTH_TOKEN", "")

    # ── Cache ─────────────────────────────────────────────────
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "300"))
    CACHE_MAX_SIZE: int = int(os.getenv("CACHE_MAX_SIZE", "1000"))

    # ── Rate Limits (requests per minute per source) ──────────
    VT_RATE_LIMIT: float = float(os.getenv("VT_RATE_LIMIT", "4"))    # free tier
    OTX_RATE_LIMIT: float = float(os.getenv("OTX_RATE_LIMIT", "60"))
    NVD_RATE_LIMIT: float = float(os.getenv("NVD_RATE_LIMIT", "5"))  # no key

    # ── Logging ───────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    AUDIT_LOG_DIR: str = os.getenv("AUDIT_LOG_DIR", "logs")

    # ── MITRE / Cache directories ────────────────────────────
    # In Docker: set MITRE_CACHE_DIR=/app/.mitre_cache (Dockerfile ENV)
    # Local dev: falls back to <project_root>/.mitre_cache
    MITRE_CACHE_DIR: str = os.getenv(
        "MITRE_CACHE_DIR",
        str(Path(__file__).parent.parent / ".mitre_cache"),
    )

    # ── Timeouts ──────────────────────────────────────────────
    HTTP_TIMEOUT: float = float(os.getenv("HTTP_TIMEOUT", "20"))

    # ── Retry ─────────────────────────────────────────────────
    HTTP_MAX_RETRIES: int = int(os.getenv("HTTP_MAX_RETRIES", "3"))

    # ── API Base URLs ─────────────────────────────────────────
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1"
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @classmethod
    def is_virustotal_enabled(cls) -> bool:
        return bool(cls.VIRUSTOTAL_API_KEY)

    @classmethod
    def is_otx_enabled(cls) -> bool:
        return bool(cls.OTX_API_KEY)

    @classmethod
    def is_nvd_enabled(cls) -> bool:
        return True  # NVD is always available (API key optional)

    @classmethod
    def is_mitre_enabled(cls) -> bool:
        return True  # MITRE ATT&CK is always available (local data)

    @classmethod
    def is_cisa_ics_enabled(cls) -> bool:
        return True  # CISA ICS RSS feed is always available

    @classmethod
    def is_mitre_ics_enabled(cls) -> bool:
        return True  # MITRE ATT&CK for ICS local data

    @classmethod
    def is_http_auth_enabled(cls) -> bool:
        return bool(cls.MCP_AUTH_TOKEN)

    @classmethod
    def get_enabled_sources(cls) -> list[str]:
        sources = []
        if cls.is_virustotal_enabled():
            sources.append("virustotal")
        if cls.is_otx_enabled():
            sources.append("otx")
        if cls.is_nvd_enabled():
            sources.append("nvd-cve")
        if cls.is_mitre_enabled():
            sources.append("mitre-attack")
        sources.append("cisa-ics")
        sources.append("mitre-ics")
        return sources


def setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


config = Config()
