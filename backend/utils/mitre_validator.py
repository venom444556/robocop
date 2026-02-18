"""MITRE ATT&CK technique validator against the official Enterprise framework."""

import json
import os
import re
import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class MITREATTACKValidator:
    """Download, cache, and validate MITRE ATT&CK technique IDs
    against the official Enterprise ATT&CK framework to reject LLM hallucinations."""

    ENTERPRISE_ATTACK_URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    def __init__(self):
        from config import get_settings
        settings = get_settings()
        self.cache_dir = settings.mitre_attack_cache_dir
        self.attack_url = settings.mitre_attack_json_url
        self._technique_map: Dict[str, Dict] = {}
        self._loaded = False

    async def _ensure_loaded(self):
        """Load ATT&CK framework data, downloading/caching as needed."""
        if self._loaded:
            return

        os.makedirs(self.cache_dir, exist_ok=True)
        cache_path = os.path.join(self.cache_dir, "enterprise-attack.json")

        # Check if cache exists and is fresh (24 hours)
        if os.path.exists(cache_path):
            mtime = os.path.getmtime(cache_path)
            age_hours = (time.time() - mtime) / 3600
            if age_hours < 24:
                self._load_from_file(cache_path)
                return

        # Try to download fresh copy
        try:
            await self._download_and_cache(cache_path)
        except Exception as e:
            logger.warning(f"Failed to download MITRE ATT&CK data: {e}")
            # Fall back to cached copy if available
            if os.path.exists(cache_path):
                logger.info("Using cached MITRE ATT&CK data")
                self._load_from_file(cache_path)
            else:
                logger.error("No MITRE ATT&CK data available")

    async def _download_and_cache(self, cache_path: str):
        """Download enterprise-attack.json from MITRE GitHub and cache locally."""
        import httpx

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(self.attack_url)
            response.raise_for_status()

            with open(cache_path, "wb") as f:
                f.write(response.content)

            logger.info("Downloaded and cached MITRE ATT&CK Enterprise data")

        self._load_from_file(cache_path)

    def _load_from_file(self, path: str):
        """Parse the STIX bundle and build technique lookup map."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = data.get("objects", [])

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            # Extract technique ID from external references
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            # Extract tactics from kill chain phases
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))

            self._technique_map[technique_id] = {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "tactic": ", ".join(tactics) if tactics else "unknown",
                "description": (obj.get("description", "") or "")[:500],
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }

        self._loaded = True
        logger.info(f"Loaded {len(self._technique_map)} MITRE ATT&CK techniques")

    async def validate_technique(self, technique_id: str) -> Dict:
        """
        Validate a single technique ID against the official framework.

        Returns:
            {"valid": bool, "technique_id": str, "name": str, "tactic": str}
        """
        await self._ensure_loaded()

        if technique_id in self._technique_map:
            info = self._technique_map[technique_id]
            return {"valid": True, **info}

        return {
            "valid": False,
            "technique_id": technique_id,
            "reason": "Not found in official MITRE ATT&CK Enterprise framework"
        }

    async def validate_techniques(self, techniques: List[Dict]) -> Dict:
        """
        Validate a list of techniques from Claude analysis.

        Args:
            techniques: List of dicts with at least an "id" key.

        Returns:
            {
                "validated": [...],     # Confirmed in official framework
                "supposition": [...],   # Valid format but not in current framework
                "invalid": [...],       # Bad format or clearly wrong
                "stats": {...}
            }
        """
        await self._ensure_loaded()

        validated = []
        supposition = []
        invalid = []

        for t in techniques:
            tid = t.get("id", "")
            result = await self.validate_technique(tid)

            if result["valid"]:
                validated.append({
                    **t,
                    "mitre_validated": True,
                    "official_name": result["name"],
                    "official_tactic": result["tactic"],
                })
            elif re.match(r'^T\d{4}(\.\d{3})?$', tid):
                # Valid format but not in current framework version
                supposition.append({
                    **t,
                    "mitre_validated": False,
                    "reason": "ID format valid but not in current ATT&CK version",
                })
            else:
                invalid.append({
                    **t,
                    "mitre_validated": False,
                    "reason": "Invalid technique ID format",
                })

        total = len(techniques)
        return {
            "validated": validated,
            "supposition": supposition,
            "invalid": invalid,
            "stats": {
                "total": total,
                "validated_count": len(validated),
                "supposition_count": len(supposition),
                "invalid_count": len(invalid),
                "validation_rate": round(
                    len(validated) / max(total, 1) * 100, 1
                ),
            },
        }

    async def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """Get full technique info including description."""
        await self._ensure_loaded()
        return self._technique_map.get(technique_id)
