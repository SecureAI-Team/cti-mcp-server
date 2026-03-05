"""
Input validation and SSRF protection for CTI MCP Server.
All Tool parameters pass through here before reaching connectors.
"""

import ipaddress
import re
import urllib.parse
from typing import Literal

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_STRING_LEN = 2048
MAX_QUERY_LEN = 256

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

_HASH_LENGTHS = {32, 40, 64}  # MD5, SHA1, SHA256

# Private / loopback IP networks — block to prevent SSRF
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_BLOCKED_SCHEMES = {"file", "ftp", "gopher", "ldap", "dict", "data", "sftp"}
_BLOCKED_DOMAINS = {"localhost", "localhost.localdomain", "local"}


class ValidationError(ValueError):
    """Raised when input validation fails."""
    pass


# ── Validators ────────────────────────────────────────────────────────────────

def validate_ip(ip: str) -> str:
    """Validate an IP address and block private/loopback ranges."""
    ip = ip.strip()
    if len(ip) > 45:
        raise ValidationError(f"IP address too long: {len(ip)} chars")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValidationError(f"Invalid IP address format: '{ip}'")

    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValidationError(
                f"Private/internal IP addresses are not supported for threat lookup: '{ip}'"
            )
    return str(addr)


def validate_domain(domain: str) -> str:
    """Validate a domain name."""
    domain = domain.strip().lower().rstrip(".")
    if len(domain) > 253:
        raise ValidationError(f"Domain name too long: {len(domain)} chars")
    if domain in _BLOCKED_DOMAINS:
        raise ValidationError(f"Reserved domain not supported: '{domain}'")
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"Invalid domain format: '{domain}'")
    return domain


def validate_hash(file_hash: str) -> str:
    """Validate a file hash (MD5/SHA1/SHA256 hex string)."""
    file_hash = file_hash.strip().lower()
    if not re.match(r"^[0-9a-f]+$", file_hash):
        raise ValidationError(f"Hash must be a hex string, got: '{file_hash[:20]}...'")
    if len(file_hash) not in _HASH_LENGTHS:
        raise ValidationError(
            f"Hash length {len(file_hash)} not recognized. "
            f"Expected MD5(32), SHA1(40), or SHA256(64)."
        )
    return file_hash


def validate_url(url: str) -> str:
    """Validate a URL and block SSRF-prone schemes and destinations."""
    url = url.strip()
    if len(url) > MAX_STRING_LEN:
        raise ValidationError(f"URL too long: {len(url)} chars (max {MAX_STRING_LEN})")

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise ValidationError(f"Malformed URL: '{url[:100]}'")

    scheme = parsed.scheme.lower()
    if scheme in _BLOCKED_SCHEMES:
        raise ValidationError(f"URL scheme '{scheme}://' is not permitted")
    if scheme not in ("http", "https", ""):
        raise ValidationError(f"Only http/https URLs are supported, got '{scheme}://'")

    hostname = parsed.hostname or ""
    if hostname in _BLOCKED_DOMAINS:
        raise ValidationError(f"Reserved hostname not supported: '{hostname}'")

    # Check if hostname is a private IP
    is_private_ip = False
    resolved_addr = None
    try:
        resolved_addr = ipaddress.ip_address(hostname)
        is_private_ip = any(resolved_addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        pass  # Not an IP address — domain form, fine

    if is_private_ip:
        raise ValidationError(
            f"URLs pointing to private IP ranges are not supported: '{hostname}'"
        )

    return url


def validate_ioc(indicator: str, ioc_type: str) -> str:
    """
    Unified IOC validator. Returns the cleaned indicator string.
    Raises ValidationError on invalid input.
    """
    if not indicator or not indicator.strip():
        raise ValidationError("Indicator cannot be empty")

    ioc_type = ioc_type.lower().strip()
    dispatch = {
        "ip": validate_ip,
        "domain": validate_domain,
        "hash": validate_hash,
        "url": validate_url,
    }
    fn = dispatch.get(ioc_type)
    if fn is None:
        raise ValidationError(
            f"Unknown ioc_type '{ioc_type}'. Must be one of: ip, domain, hash, url"
        )
    return fn(indicator)


def validate_cve_id(cve_id: str) -> str:
    """Validate CVE ID format (CVE-YYYY-NNNNN)."""
    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise ValidationError(
            f"Invalid CVE ID format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN"
        )
    return cve_id


def validate_technique_id(technique_id: str) -> str:
    """Validate MITRE ATT&CK technique ID (T#### or T####.###)."""
    technique_id = technique_id.strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", technique_id):
        raise ValidationError(
            f"Invalid technique ID: '{technique_id}'. Expected format: T1059 or T1059.001"
        )
    return technique_id


def validate_query_string(query: str, field: str = "query") -> str:
    """Validate a free-text search query."""
    query = query.strip()
    if not query:
        raise ValidationError(f"'{field}' cannot be empty")
    if len(query) > MAX_QUERY_LEN:
        raise ValidationError(
            f"'{field}' too long: {len(query)} chars (max {MAX_QUERY_LEN})"
        )
    return query


def sanitize_error(exc: Exception) -> str:
    """
    Return a safe error message — strips file paths and potential secrets.
    Never expose internal stack traces or API keys to Tool callers.
    """
    msg = str(exc)
    # Redact anything that looks like an API key (long hex strings)
    msg = re.sub(r"\b[0-9a-fA-F]{20,}\b", "[REDACTED]", msg)
    # Redact Windows-style paths
    msg = re.sub(r"[A-Za-z]:\\[^\s]+", "[PATH]", msg)
    # Redact Unix-style paths  
    msg = re.sub(r"/(?:home|root|usr|var|etc)/[^\s]+", "[PATH]", msg)
    # Truncate if still too long
    if len(msg) > 300:
        msg = msg[:297] + "..."
    return msg
