"""GreyNoise Community API client for IP noise/threat classification."""

from typing import Dict, Optional


class GreyNoiseClient:
    """Client for GreyNoise Community API (free, unlimited with API key)."""

    BASE_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize GreyNoise client.

        Args:
            api_key: GreyNoise API key (free account = unlimited community lookups)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.greynoise_api_key

    async def lookup_ip(self, ip_address: str) -> Dict:
        """
        Check if an IP is internet background noise or a targeted threat.

        Args:
            ip_address: IP address to look up

        Returns:
            Dictionary with noise classification
        """
        import httpx

        if not self.api_key:
            return {"error": "GreyNoise API key not configured"}

        headers = {
            "Accept": "application/json",
            "key": self.api_key
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/{ip_address}",
                    headers=headers
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._format_response(ip_address, data)
                elif response.status_code == 404:
                    return {
                        "ip": ip_address,
                        "found": False,
                        "noise": False,
                        "riot": False,
                        "classification": "unknown",
                        "message": "IP not observed by GreyNoise",
                        "source": "greynoise"
                    }
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def _format_response(self, ip_address: str, data: Dict) -> Dict:
        """Format the GreyNoise API response."""
        return {
            "ip": ip_address,
            "found": True,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
            "source": "greynoise"
        }

    def interpret_classification(self, classification: str) -> Dict:
        """
        Interpret a GreyNoise classification for SOC analysts.

        Args:
            classification: GreyNoise classification string

        Returns:
            Dictionary with interpretation
        """
        interpretations = {
            "benign": {
                "level": "safe",
                "description": "Known benign service (e.g., search engine crawler, CDN).",
                "action": "allow"
            },
            "malicious": {
                "level": "critical",
                "description": "IP observed conducting malicious activity (scanning, exploitation).",
                "action": "block"
            },
            "unknown": {
                "level": "low",
                "description": "IP not seen mass-scanning. Could be targeted or simply not observed.",
                "action": "investigate"
            }
        }
        return interpretations.get(classification, {
            "level": "unknown",
            "description": f"Unrecognized classification: {classification}",
            "action": "investigate"
        })
