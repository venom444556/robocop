"""AlienVault OTX (Open Threat Exchange) API client for threat intelligence."""

from typing import Dict, List, Optional


class AlienVaultOTXClient:
    """Client for AlienVault OTX DirectConnect API (free, unlimited)."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize AlienVault OTX client.

        Args:
            api_key: OTX API key (free account at otx.alienvault.com)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.alienvault_otx_api_key

    async def _make_request(self, endpoint: str) -> Dict:
        """Make an API request to OTX."""
        import httpx

        if not self.api_key:
            return {"error": "AlienVault OTX API key not configured"}

        headers = {
            "Accept": "application/json",
            "X-OTX-API-KEY": self.api_key
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/{endpoint}",
                    headers=headers
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    return {"error": "Not found", "status_code": 404}
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def lookup_ip(self, ip_address: str) -> Dict:
        """
        Get threat intelligence for an IP address.

        Args:
            ip_address: IP address to look up

        Returns:
            Dictionary with OTX intelligence
        """
        general = await self._make_request(f"indicators/IPv4/{ip_address}/general")
        if "error" in general:
            return general

        reputation = await self._make_request(f"indicators/IPv4/{ip_address}/reputation")

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        pulses = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:10]:
            pulses.append({
                "id": pulse.get("id"),
                "name": pulse.get("name"),
                "description": pulse.get("description", "")[:200],
                "created": pulse.get("created"),
                "tags": pulse.get("tags", [])[:10],
                "adversary": pulse.get("adversary"),
                "targeted_countries": pulse.get("targeted_countries", []),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", [])
            })

        rep_data = reputation if not reputation.get("error") else {}

        return {
            "ip": ip_address,
            "found": True,
            "country": general.get("country_name"),
            "country_code": general.get("country_code"),
            "asn": general.get("asn"),
            "pulse_count": pulse_count,
            "pulses": pulses,
            "reputation_score": rep_data.get("reputation", {}).get("threat_score") if rep_data.get("reputation") else None,
            "whois": general.get("whois"),
            "source": "alienvault_otx"
        }

    async def lookup_domain(self, domain: str) -> Dict:
        """
        Get threat intelligence for a domain.

        Args:
            domain: Domain to look up

        Returns:
            Dictionary with OTX intelligence
        """
        general = await self._make_request(f"indicators/domain/{domain}/general")
        if "error" in general:
            return general

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        pulses = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:10]:
            pulses.append({
                "id": pulse.get("id"),
                "name": pulse.get("name"),
                "description": pulse.get("description", "")[:200],
                "created": pulse.get("created"),
                "tags": pulse.get("tags", [])[:10],
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", [])
            })

        return {
            "domain": domain,
            "found": True,
            "whois": general.get("whois"),
            "pulse_count": pulse_count,
            "pulses": pulses,
            "alexa": general.get("alexa"),
            "source": "alienvault_otx"
        }

    async def lookup_hash(self, file_hash: str) -> Dict:
        """
        Get threat intelligence for a file hash.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dictionary with OTX intelligence
        """
        # Determine hash type for API endpoint
        hash_len = len(file_hash)
        if hash_len == 32:
            hash_type = "file"  # OTX uses "file" for all hash types
        elif hash_len == 40:
            hash_type = "file"
        elif hash_len == 64:
            hash_type = "file"
        else:
            return {"error": f"Invalid hash length: {hash_len}"}

        general = await self._make_request(f"indicators/{hash_type}/{file_hash}/general")
        if "error" in general:
            return general

        analysis = await self._make_request(f"indicators/{hash_type}/{file_hash}/analysis")

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        pulses = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:10]:
            pulses.append({
                "id": pulse.get("id"),
                "name": pulse.get("name"),
                "description": pulse.get("description", "")[:200],
                "tags": pulse.get("tags", [])[:10],
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", [])
            })

        analysis_data = analysis if not analysis.get("error") else {}
        analysis_info = analysis_data.get("analysis", {}) if analysis_data else {}

        return {
            "hash": file_hash,
            "found": True,
            "pulse_count": pulse_count,
            "pulses": pulses,
            "malware_families": analysis_info.get("plugins", {}).get("cuckoo", {}).get("result", {}).get("malfamily") if analysis_info.get("plugins") else None,
            "source": "alienvault_otx"
        }

    async def lookup_url(self, url: str) -> Dict:
        """
        Get threat intelligence for a URL.

        Args:
            url: URL to look up

        Returns:
            Dictionary with OTX intelligence
        """
        general = await self._make_request(f"indicators/url/{url}/general")
        if "error" in general:
            return general

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        pulses = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:10]:
            pulses.append({
                "id": pulse.get("id"),
                "name": pulse.get("name"),
                "description": pulse.get("description", "")[:200],
                "tags": pulse.get("tags", [])[:10],
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", [])
            })

        return {
            "url": url,
            "found": True,
            "pulse_count": pulse_count,
            "pulses": pulses,
            "source": "alienvault_otx"
        }
