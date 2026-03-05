"""
MAC OUI / Vendor Fingerprinting for OT/ICS assets.
Downloads the IEEE MA-L standard public OUI list and caches it.
"""

import logging
import re
from pathlib import Path

import httpx

from ..cache import cached
from ..config import config

logger = logging.getLogger(__name__)

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

_CACHE_DIR = Path(config.MITRE_CACHE_DIR) if getattr(config, "MITRE_CACHE_DIR", None) else Path(".mitre_cache")
_OUI_CACHE_FILE = _CACHE_DIR / "oui.txt"


class MacOUIConnector:
    """Offline lookup of MAC OUI to OT/IT Manufacturer."""
    
    def __init__(self) -> None:
        self._db: dict[str, str] = {}
        self._loaded = False
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def _load_db(self) -> None:
        if self._loaded:
            return

        if not _OUI_CACHE_FILE.exists():
            logger.info("Downloading IEEE OUI database (first run)...")
            async with httpx.AsyncClient(timeout=120.0) as client:
                try:
                    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    resp = await client.get(IEEE_OUI_URL, follow_redirects=True)
                    resp.raise_for_status()
                    _OUI_CACHE_FILE.write_bytes(resp.content)
                    logger.info("OUI database downloaded successfully.")
                except Exception as exc:
                    logger.error("Failed to download OUI database: %s", exc)

        if not _OUI_CACHE_FILE.exists():
            return

        try:
            with open(_OUI_CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) >= 2:
                            prefix = parts[0].strip().replace("-", "").upper()
                            vendor = parts[1].strip()
                            if len(prefix) == 6 and vendor:
                                self._db[prefix] = vendor
            self._loaded = True
            logger.info("OUI database loaded with %d entries.", len(self._db))
        except Exception as exc:
            logger.error("Failed to parse OUI database: %s", exc)

    @cached
    async def lookup_mac(self, mac_address: str) -> dict[str, str | bool]:
        """Look up the vendor of a given MAC address."""
        await self._load_db()
        
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac_address).upper()
        if len(cleaned) < 6:
            return {"error": f"Invalid MAC address format: '{mac_address}'"}
            
        prefix = cleaned[:6]
        vendor = self._db.get(prefix)
        
        if not vendor:
            return {
                "mac_address": mac_address,
                "oui_prefix": prefix,
                "found": False,
                "vendor": "Unknown / Private",
            }
            
        return {
            "mac_address": mac_address,
            "oui_prefix": prefix,
            "found": True,
            "vendor": vendor,
        }
