"""
MITRE ATT&CK connector using mitreattack-python.
Downloads and caches ATT&CK STIX data locally.
Works entirely offline after the first run.
"""

import logging
from pathlib import Path
from typing import Any

from ..config import config
from ..models import MitreTactic, MitreTechnique, MitreGroup

logger = logging.getLogger(__name__)

# Local cache path for ATT&CK STIX data (respects MITRE_CACHE_DIR env var)
_STIX_CACHE_DIR = Path(config.MITRE_CACHE_DIR)
_STIX_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


class MitreAttackConnector:
    """
    Wrapper around mitreattack-python.
    Uses the STIX data from MITRE's GitHub repo, cached locally.
    """

    def __init__(self) -> None:
        self._src: Any = None  # MitreAttackData instance (lazy loaded)

    def _load(self) -> Any:
        if self._src is not None:
            return self._src

        try:
            from mitreattack.stix20 import MitreAttackData

            stix_file = _STIX_CACHE_DIR / "enterprise-attack.json"
            if not stix_file.exists():
                logger.info("Downloading MITRE ATT&CK STIX data (first run)...")
                import httpx
                resp = httpx.get(_ENTERPRISE_STIX_URL, timeout=60, follow_redirects=True)
                resp.raise_for_status()
                stix_file.write_bytes(resp.content)
                logger.info("MITRE ATT&CK STIX data downloaded (%d bytes)", len(resp.content))

            self._src = MitreAttackData(str(stix_file))
            logger.info("MITRE ATT&CK data loaded successfully")
            return self._src
        except ImportError:
            logger.error("mitreattack-python is not installed. Run: pip install mitreattack-python")
            return None
        except Exception as exc:
            logger.error("Failed to load MITRE ATT&CK data: %s", exc)
            return None

    def get_tactics(self) -> list[MitreTactic]:
        """Return all ATT&CK Enterprise tactics."""
        src = self._load()
        if not src:
            return []
        try:
            tactics = src.get_tactics(remove_revoked_deprecated=True)
            result = []
            for t in tactics:
                ext = t.get("external_references", [{}])[0]
                result.append(MitreTactic(
                    id=ext.get("external_id", ""),
                    name=t.get("name", ""),
                    short_name=t.get("x_mitre_shortname", ""),
                    description=t.get("description", ""),
                    url=ext.get("url", ""),
                ))
            return sorted(result, key=lambda x: x.id)
        except Exception as exc:
            logger.error("get_tactics failed: %s", exc)
            return []

    def get_technique(self, technique_id: str) -> MitreTechnique | None:
        """Get a specific technique by ATT&CK ID (e.g. T1059 or T1059.001)."""
        src = self._load()
        if not src:
            return None
        try:
            technique = src.get_object_by_attack_id(technique_id, "attack-pattern")
            if not technique:
                return None
            return self._parse_technique(technique)
        except Exception as exc:
            logger.error("get_technique(%s) failed: %s", technique_id, exc)
            return None

    def search_techniques(self, query: str, limit: int = 10) -> list[MitreTechnique]:
        """Full-text search across technique names and descriptions."""
        src = self._load()
        if not src:
            return []
        query_lower = query.lower()
        try:
            all_techniques = src.get_techniques(remove_revoked_deprecated=True)
            matches = []
            for t in all_techniques:
                name = t.get("name", "")
                desc = t.get("description", "")
                if query_lower in name.lower() or query_lower in desc.lower():
                    parsed = self._parse_technique(t)
                    if parsed:
                        matches.append(parsed)
                if len(matches) >= limit:
                    break
            return matches
        except Exception as exc:
            logger.error("search_techniques failed: %s", exc)
            return []

    def get_techniques_by_tactic(self, tactic_short_name: str, limit: int = 50) -> list[MitreTechnique]:
        """Get all techniques belonging to a specific tactic (e.g. 'execution', 'persistence')."""
        src = self._load()
        if not src:
            return []
        try:
            techniques = src.get_techniques_by_tactic(
                tactic_short_name, domain="enterprise-attack", remove_revoked_deprecated=True
            )
            return [self._parse_technique(t) for t in techniques[:limit] if t]
        except Exception as exc:
            logger.error("get_techniques_by_tactic(%s) failed: %s", tactic_short_name, exc)
            return []

    def _parse_technique(self, t: Any) -> MitreTechnique | None:
        try:
            ext_refs = t.get("external_references", [])
            attack_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
            technique_id = attack_ref.get("external_id", "")
            url = attack_ref.get("url", "")

            kill_chain_phases = t.get("kill_chain_phases", [])
            tactics = [p.get("phase_name", "") for p in kill_chain_phases]

            is_subtechnique = "." in technique_id
            parent_id = technique_id.split(".")[0] if is_subtechnique else None

            data_sources = t.get("x_mitre_data_sources", [])

            return MitreTechnique(
                id=technique_id,
                name=t.get("name", ""),
                description=t.get("description", ""),
                platforms=t.get("x_mitre_platforms", []),
                tactics=tactics,
                is_subtechnique=is_subtechnique,
                parent_id=parent_id,
                detection=t.get("x_mitre_detection", ""),
                url=url,
                data_sources=data_sources[:10],
            )
        except Exception as exc:
            logger.error("_parse_technique failed: %s", exc)
            return None

    def get_groups(self, limit: int = 50) -> list[MitreGroup]:
        """Return all ATT&CK Enterprise threat actors (groups)."""
        src = self._load()
        if not src:
            return []
        try:
            groups = src.get_groups(remove_revoked_deprecated=True)
            return [self._parse_group(g) for g in groups[:limit] if g]
        except Exception as exc:
            logger.error("get_groups failed: %s", exc)
            return []
            
    def search_groups(self, query: str, limit: int = 10) -> list[MitreGroup]:
        """Search APT groups by name or alias."""
        src = self._load()
        if not src:
            return []
        query_lower = query.lower()
        try:
            groups = src.get_groups(remove_revoked_deprecated=True)
            matches = []
            for g in groups:
                name = g.get("name", "").lower()
                aliases = [a.lower() for a in g.get("aliases", [])]
                desc = g.get("description", "").lower()
                
                if query_lower in name or any(query_lower in a for a in aliases) or query_lower in desc:
                    parsed = self._parse_group(g)
                    if parsed:
                        matches.append(parsed)
                if len(matches) >= limit:
                    break
            return matches
        except Exception as exc:
            logger.error("search_groups failed: %s", exc)
            return []

    def _parse_group(self, g: Any) -> MitreGroup | None:
        try:
            ext_refs = g.get("external_references", [])
            attack_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
            group_id = attack_ref.get("external_id", "")
            url = attack_ref.get("url", "")
            
            return MitreGroup(
                id=group_id,
                name=g.get("name", ""),
                description=g.get("description", ""),
                aliases=g.get("aliases", []),
                url=url
            )
        except Exception as exc:
            logger.error("_parse_group failed: %s", exc)
            return None
