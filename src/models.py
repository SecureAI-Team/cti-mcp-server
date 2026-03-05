"""
Pydantic data models for CTI MCP Server.
All connector results are normalized into these models.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


# ── Common ────────────────────────────────────────────────────────────────────

class SourceResult(BaseModel):
    """Result from a single data source."""
    source: str
    available: bool
    data: dict[str, Any] | None = None
    error: str | None = None


# ── IOC / Indicator ───────────────────────────────────────────────────────────

class VTDetection(BaseModel):
    """VirusTotal detection summary."""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0

    @property
    def verdict(self) -> str:
        if self.total == 0:
            return "unknown"
        ratio = self.malicious / self.total
        if ratio >= 0.5:
            return "malicious"
        elif ratio >= 0.1 or self.suspicious > 2:
            return "suspicious"
        return "clean"

    @property
    def detection_rate(self) -> str:
        if self.total == 0:
            return "0/0"
        return f"{self.malicious}/{self.total}"


class OTXContext(BaseModel):
    """AlienVault OTX indicator context."""
    pulse_count: int = 0
    pulse_titles: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_score: int = 0  # 0-100


class IOCResult(BaseModel):
    """Unified IOC query result."""
    indicator: str
    ioc_type: IOCType
    query_time: datetime = Field(default_factory=datetime.utcnow)

    # VirusTotal
    vt: VTDetection | None = None
    vt_tags: list[str] = Field(default_factory=list)
    vt_categories: dict[str, str] = Field(default_factory=dict)

    # OTX
    otx: OTXContext | None = None

    # Aggregated
    threat_score: int = 0  # 0-100, higher = more malicious
    verdict: str = "unknown"  # malicious / suspicious / clean / unknown
    sources_queried: list[str] = Field(default_factory=list)
    sources_unavailable: list[str] = Field(default_factory=list)

    def compute_verdict(self) -> None:
        """Compute aggregated verdict from all available sources."""
        scores = []
        if self.vt and self.vt.total > 0:
            vt_score = int((self.vt.malicious / self.vt.total) * 100)
            scores.append(vt_score)
        if self.otx:
            scores.append(self.otx.threat_score)

        if not scores:
            self.verdict = "unknown"
            self.threat_score = 0
            return

        self.threat_score = max(scores)
        if self.threat_score >= 60:
            self.verdict = "malicious"
        elif self.threat_score >= 25:
            self.verdict = "suspicious"
        else:
            self.verdict = "clean"


# ── CVE ───────────────────────────────────────────────────────────────────────

class CVSSScore(BaseModel):
    version: str  # "3.1", "3.0", "2.0"
    base_score: float
    severity: Severity
    vector_string: str = ""
    exploitability_score: float | None = None
    impact_score: float | None = None


class CPEMatch(BaseModel):
    cpe: str
    vulnerable: bool = True
    version_start: str | None = None
    version_end: str | None = None


class CVEResult(BaseModel):
    """CVE vulnerability details."""
    cve_id: str
    description: str
    published: datetime | None = None
    last_modified: datetime | None = None
    cvss: list[CVSSScore] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    affected_products: list[CPEMatch] = Field(default_factory=list)
    source: str = "nvd"

    @property
    def highest_cvss_score(self) -> float | None:
        if not self.cvss:
            return None
        return max(c.base_score for c in self.cvss)

    @property
    def highest_severity(self) -> Severity:
        if not self.cvss:
            return Severity.UNKNOWN
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE]
        for sev in order:
            if any(c.severity == sev for c in self.cvss):
                return sev
        return Severity.UNKNOWN


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

class MitreTactic(BaseModel):
    id: str
    name: str
    short_name: str
    description: str
    url: str = ""


class MitreTechnique(BaseModel):
    id: str
    name: str
    description: str
    platforms: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: str | None = None
    detection: str = ""
    mitigation_ids: list[str] = Field(default_factory=list)
    url: str = ""
    data_sources: list[str] = Field(default_factory=list)


# ── OTX Pulse ─────────────────────────────────────────────────────────────────

class OTXIndicator(BaseModel):
    indicator: str
    type: str
    description: str = ""


class OTXPulse(BaseModel):
    id: str
    name: str
    description: str
    author: str
    tlp: str = "white"
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    indicators: list[OTXIndicator] = Field(default_factory=list)
    created: datetime | None = None
    modified: datetime | None = None
    indicator_count: int = 0
    source: str = "otx"


# ── Service Status ─────────────────────────────────────────────────────────────

class DataSourceStatus(BaseModel):
    name: str
    enabled: bool
    description: str


class ServiceStatus(BaseModel):
    server_name: str
    version: str = "0.1.0"
    data_sources: list[DataSourceStatus]
    cache_ttl_seconds: int
