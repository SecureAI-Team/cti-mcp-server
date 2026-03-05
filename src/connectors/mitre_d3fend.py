"""
MITRE D3FEND connector mapped to ATT&CK Enterprise.
Provides defensive countermeasures and security actions tailored to specific ATT&CK techniques.
"""

import logging
from typing import Any

import httpx

from ..cache import cached
from ..config import config

logger = logging.getLogger(__name__)

D3FEND_API_BASE = "https://d3fend.mitre.org/api/offensive-technique/attack/"


class MitreD3fendConnector:
    """Query MITRE D3FEND countermeasures for a given ATT&CK technique."""

    def __init__(self) -> None:
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    @cached
    async def get_defenses_for_technique(self, technique_id: str) -> dict[str, Any]:
        """
        Query D3FEND for countermeasures mapped to a MITRE ATT&CK technique.
        Returns the specific security mechanisms that can detect or mitigate the behavior.
        """
        technique_id = technique_id.upper().strip()
        url = f"{D3FEND_API_BASE}{technique_id}.json"

        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(url, follow_redirects=True)
                if resp.status_code == 404:
                    return {"technique": technique_id, "defenses": []}
                resp.raise_for_status()
                data = resp.json()
                
                # Extract countermeasure info
                bindings = data.get("off_to_def", {}).get("bindings", [])
                
                defenses = []
                for b in bindings:
                    def_tech = b.get("def_tech", {})
                    label = def_tech.get("label", "Unknown Defense")
                    d3fend_id = def_tech.get("id", "").split("#")[-1]
                    
                    if label not in [d["name"] for d in defenses]:
                        defenses.append({
                            "id": d3fend_id,
                            "name": label,
                            "url": f"https://d3fend.mitre.org/technique/d3fend:{d3fend_id}" if d3fend_id else ""
                        })
                        
                return {
                    "technique": technique_id,
                    "defenses_count": len(defenses),
                    "defenses": defenses
                }
            except httpx.HTTPError as exc:
                logger.error("D3FEND API HTTP Error for %s: %s", technique_id, exc)
                return {"error": f"D3FEND API error: {exc}"}
            except Exception as exc:
                logger.error("D3FEND query failed for %s: %s", technique_id, exc)
                return {"error": "Internal error during D3FEND query"}
