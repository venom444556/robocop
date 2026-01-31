"""Google Safe Browsing API client for phishing/malware URL detection."""

from typing import Dict, List, Optional


class GoogleSafeBrowsingClient:
    """Client for Google Safe Browsing API v4."""

    BASE_URL = "https://safebrowsing.googleapis.com/v4"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Google Safe Browsing client.

        Args:
            api_key: Google API key with Safe Browsing API enabled
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.google_safebrowsing_api_key

    async def check_urls(self, urls: List[str]) -> Dict:
        """
        Check multiple URLs against Safe Browsing lists.

        Args:
            urls: List of URLs to check (max 500)

        Returns:
            Dictionary with threat matches
        """
        import httpx

        if not self.api_key:
            return {"error": "Google Safe Browsing API key not configured"}

        if len(urls) > 500:
            urls = urls[:500]

        url = f"{self.BASE_URL}/threatMatches:find"
        params = {"key": self.api_key}

        # Build request body
        body = {
            "client": {
                "clientId": "malware-analysis-platform",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, params=params, json=body)

                if response.status_code == 200:
                    data = response.json()
                    return self._format_response(urls, data)
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def _format_response(self, checked_urls: List[str], response: Dict) -> Dict:
        """Format the Safe Browsing API response."""
        matches = response.get("matches", [])

        # Create a map of URL to threats
        threat_map = {}
        for match in matches:
            url = match.get("threat", {}).get("url")
            if url:
                if url not in threat_map:
                    threat_map[url] = []
                threat_map[url].append({
                    "threat_type": match.get("threatType"),
                    "platform_type": match.get("platformType"),
                    "cache_duration": match.get("cacheDuration")
                })

        # Build results for all checked URLs
        results = []
        for url in checked_urls:
            if url in threat_map:
                results.append({
                    "url": url,
                    "safe": False,
                    "threats": threat_map[url]
                })
            else:
                results.append({
                    "url": url,
                    "safe": True,
                    "threats": []
                })

        # Summary
        unsafe_count = len(threat_map)

        return {
            "checked_count": len(checked_urls),
            "unsafe_count": unsafe_count,
            "safe_count": len(checked_urls) - unsafe_count,
            "results": results,
            "source": "google_safebrowsing"
        }

    async def check_url(self, url: str) -> Dict:
        """
        Check a single URL against Safe Browsing lists.

        Args:
            url: URL to check

        Returns:
            Dictionary with threat info
        """
        result = await self.check_urls([url])

        if "error" in result:
            return result

        url_result = result.get("results", [{}])[0]

        return {
            "url": url,
            "safe": url_result.get("safe", True),
            "threats": url_result.get("threats", []),
            "threat_types": [t.get("threat_type") for t in url_result.get("threats", [])],
            "source": "google_safebrowsing"
        }

    async def get_threat_list_updates(self) -> Dict:
        """
        Get updates to threat lists (for local database sync).

        Returns:
            Dictionary with threat list info
        """
        import httpx

        if not self.api_key:
            return {"error": "Google Safe Browsing API key not configured"}

        url = f"{self.BASE_URL}/threatLists"
        params = {"key": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, params=params)

                if response.status_code == 200:
                    data = response.json()
                    threat_lists = []
                    for tl in data.get("threatLists", []):
                        threat_lists.append({
                            "threat_type": tl.get("threatType"),
                            "platform_type": tl.get("platformType"),
                            "threat_entry_type": tl.get("threatEntryType")
                        })
                    return {
                        "threat_lists": threat_lists,
                        "source": "google_safebrowsing"
                    }
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def interpret_threat_type(self, threat_type: str) -> str:
        """
        Get human-readable description of a threat type.

        Args:
            threat_type: Google Safe Browsing threat type

        Returns:
            Human-readable description
        """
        descriptions = {
            "MALWARE": "This URL hosts malware that can harm your computer or steal data.",
            "SOCIAL_ENGINEERING": "This URL is involved in phishing or deceptive practices to steal credentials.",
            "UNWANTED_SOFTWARE": "This URL distributes unwanted software that may affect browser settings or performance.",
            "POTENTIALLY_HARMFUL_APPLICATION": "This URL hosts potentially harmful applications.",
            "THREAT_TYPE_UNSPECIFIED": "Unspecified threat detected."
        }
        return descriptions.get(threat_type, f"Unknown threat type: {threat_type}")
