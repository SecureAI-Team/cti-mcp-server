"""
MITRE ATT&CK for ICS connector.
Uses the ICS-specific ATT&CK STIX bundle from MITRE's CTI repository.
Covers OT/SCADA-specific techniques not in the enterprise matrix.
"""

import logging
from pathlib import Path
from typing import Any

import httpx

from ..config import config
from ..models import MitreTactic, MitreTechnique

logger = logging.getLogger(__name__)

_STIX_CACHE_DIR = Path(config.MITRE_CACHE_DIR)
_STIX_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_ICS_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
)
_ICS_STIX_FILE = _STIX_CACHE_DIR / "ics-attack.json"


class MitreICSConnector:
    """
    MITRE ATT&CK for ICS connector.
    Loads STIX 2.0 data from a local cache (auto-downloads on first use).
    """

    def __init__(self) -> None:
        self._src: Any = None

    def _load(self) -> Any:
        if self._src is not None:
            return self._src

        try:
            from mitreattack.stix20 import MitreAttackData  # type: ignore

            if not _ICS_STIX_FILE.exists():
                logger.info("Downloading MITRE ATT&CK for ICS STIX data (first run)...")
                resp = httpx.get(_ICS_STIX_URL, timeout=60, follow_redirects=True)
                resp.raise_for_status()
                _ICS_STIX_FILE.write_bytes(resp.content)
                logger.info("ATT&CK for ICS STIX downloaded (%d bytes)", len(resp.content))

            self._src = MitreAttackData(str(_ICS_STIX_FILE))
            logger.info("MITRE ATT&CK for ICS data loaded")
            return self._src

        except ImportError:
            logger.error("mitreattack-python not installed")
            return None
        except Exception as exc:
            logger.error("Failed to load ATT&CK for ICS data: %s", exc)
            return None

    def get_tactics(self) -> list[MitreTactic]:
        """Return all ATT&CK for ICS tactics."""
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
            logger.error("ICS get_tactics failed: %s", exc)
            return []

    def get_technique(self, technique_id: str) -> MitreTechnique | None:
        """Get an ICS technique by ATT&CK ID (e.g. T0855)."""
        src = self._load()
        if not src:
            return None
        try:
            technique = src.get_object_by_attack_id(technique_id, "attack-pattern")
            if not technique:
                return None
            return self._parse_technique(technique)
        except Exception as exc:
            logger.error("ICS get_technique(%s) failed: %s", technique_id, exc)
            return None

    def search_techniques(self, query: str, limit: int = 10) -> list[MitreTechnique]:
        """Full-text search across ICS technique names and descriptions."""
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
            logger.error("ICS search_techniques failed: %s", exc)
            return []

    def get_techniques_by_tactic(self, tactic_short_name: str) -> list[MitreTechnique]:
        src = self._load()
        if not src:
            return []
        try:
            techniques = src.get_techniques_by_tactic(
                tactic_short_name, domain="ics-attack", remove_revoked_deprecated=True
            )
            return [self._parse_technique(t) for t in techniques if t]
        except Exception as exc:
            logger.error("ICS get_techniques_by_tactic(%s) failed: %s", tactic_short_name, exc)
            return []

    def _parse_technique(self, t: Any) -> MitreTechnique | None:
        try:
            ext_refs = t.get("external_references", [])
            attack_ref = next(
                (r for r in ext_refs if r.get("source_name") == "mitre-ics-attack"), {}
            )
            technique_id = attack_ref.get("external_id", "")
            url = attack_ref.get("url", "")

            kill_chain_phases = t.get("kill_chain_phases", [])
            tactics = [p.get("phase_name", "") for p in kill_chain_phases]

            return MitreTechnique(
                id=technique_id,
                name=t.get("name", ""),
                description=t.get("description", ""),
                platforms=t.get("x_mitre_platforms", []),
                tactics=tactics,
                is_subtechnique="." in technique_id,
                parent_id=technique_id.split(".")[0] if "." in technique_id else None,
                detection=t.get("x_mitre_detection", ""),
                url=url,
                data_sources=t.get("x_mitre_data_sources", [])[:10],
            )
        except Exception as exc:
            logger.error("ICS _parse_technique failed: %s", exc)
            return None
