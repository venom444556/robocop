"""VirusTotal API client for IOC enrichment."""

import asyncio
from typing import Dict, Optional, Any
from datetime import datetime


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key (free tier: 4 requests/minute)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.virustotal_api_key
        self.rate_limit = settings.virustotal_rate_limit
        self._last_request_time = 0

    async def _rate_limit_wait(self):
        """Wait to respect rate limits."""
        now = asyncio.get_event_loop().time()
        time_since_last = now - self._last_request_time
        min_interval = 60 / self.rate_limit  # seconds between requests

        if time_since_last < min_interval:
            await asyncio.sleep(min_interval - time_since_last)

        self._last_request_time = asyncio.get_event_loop().time()

    async def _make_request(self, endpoint: str, method: str = "GET", data: Dict = None) -> Dict:
        """Make an API request to VirusTotal."""
        import httpx

        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}

        await self._rate_limit_wait()

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        url = f"{self.BASE_URL}/{endpoint}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers)
                elif method == "POST":
                    response = await client.post(url, headers=headers, json=data)
                else:
                    return {"error": f"Unsupported method: {method}"}

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    return {"error": "Not found", "status_code": 404}
                elif response.status_code == 429:
                    return {"error": "Rate limit exceeded", "status_code": 429}
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def lookup_hash(self, file_hash: str) -> Dict:
        """
        Look up a file hash (MD5, SHA1, or SHA256).

        Args:
            file_hash: The hash to look up

        Returns:
            Dictionary with VT results
        """
        result = await self._make_request(f"files/{file_hash}")

        if "error" in result:
            return result

        data = result.get("data", {})
        attributes = data.get("attributes", {})

        return {
            "found": True,
            "hash": file_hash,
            "sha256": attributes.get("sha256"),
            "sha1": attributes.get("sha1"),
            "md5": attributes.get("md5"),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "names": attributes.get("names", [])[:10],
            "last_analysis_date": datetime.fromtimestamp(
                attributes.get("last_analysis_date", 0)
            ).isoformat() if attributes.get("last_analysis_date") else None,
            "detection_stats": attributes.get("last_analysis_stats", {}),
            "total_detections": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "total_engines": sum(attributes.get("last_analysis_stats", {}).values()),
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags", []),
            "popular_threat_names": attributes.get("popular_threat_classification", {}).get(
                "suggested_threat_label"
            ),
            "sandbox_verdicts": self._extract_sandbox_verdicts(attributes),
            "source": "virustotal"
        }

    def _extract_sandbox_verdicts(self, attributes: Dict) -> list:
        """Extract sandbox verdicts from VT attributes."""
        verdicts = []
        sandbox_results = attributes.get("sandbox_verdicts", {})

        for sandbox, verdict in sandbox_results.items():
            verdicts.append({
                "sandbox": sandbox,
                "category": verdict.get("category"),
                "confidence": verdict.get("confidence"),
                "malware_names": verdict.get("malware_names", [])
            })

        return verdicts

    async def lookup_url(self, url: str) -> Dict:
        """
        Look up a URL.

        Args:
            url: The URL to analyze

        Returns:
            Dictionary with VT results
        """
        import base64

        # VT uses base64-encoded URLs as identifiers
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        result = await self._make_request(f"urls/{url_id}")

        if result.get("status_code") == 404:
            # URL not in VT database, submit for analysis
            return await self.scan_url(url)

        if "error" in result:
            return result

        data = result.get("data", {})
        attributes = data.get("attributes", {})

        return {
            "found": True,
            "url": url,
            "final_url": attributes.get("last_final_url"),
            "last_analysis_date": datetime.fromtimestamp(
                attributes.get("last_analysis_date", 0)
            ).isoformat() if attributes.get("last_analysis_date") else None,
            "detection_stats": attributes.get("last_analysis_stats", {}),
            "total_detections": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "total_engines": sum(attributes.get("last_analysis_stats", {}).values()),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "threat_names": attributes.get("threat_names", []),
            "source": "virustotal"
        }

    async def scan_url(self, url: str) -> Dict:
        """
        Submit a URL for scanning.

        Args:
            url: URL to scan

        Returns:
            Dictionary with scan submission result
        """
        result = await self._make_request("urls", method="POST", data={"url": url})

        if "error" in result:
            return result

        data = result.get("data", {})

        return {
            "submitted": True,
            "url": url,
            "analysis_id": data.get("id"),
            "message": "URL submitted for analysis. Check back in a few minutes.",
            "source": "virustotal"
        }

    async def lookup_domain(self, domain: str) -> Dict:
        """
        Look up a domain.

        Args:
            domain: Domain to look up

        Returns:
            Dictionary with VT results
        """
        result = await self._make_request(f"domains/{domain}")

        if "error" in result:
            return result

        data = result.get("data", {})
        attributes = data.get("attributes", {})

        return {
            "found": True,
            "domain": domain,
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "last_update_date": attributes.get("last_update_date"),
            "last_analysis_date": datetime.fromtimestamp(
                attributes.get("last_analysis_date", 0)
            ).isoformat() if attributes.get("last_analysis_date") else None,
            "detection_stats": attributes.get("last_analysis_stats", {}),
            "total_detections": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories", {}),
            "popularity_ranks": attributes.get("popularity_ranks", {}),
            "whois": attributes.get("whois", "")[:1000],  # Truncate WHOIS
            "source": "virustotal"
        }

    async def lookup_ip(self, ip_address: str) -> Dict:
        """
        Look up an IP address.

        Args:
            ip_address: IP to look up

        Returns:
            Dictionary with VT results
        """
        result = await self._make_request(f"ip_addresses/{ip_address}")

        if "error" in result:
            return result

        data = result.get("data", {})
        attributes = data.get("attributes", {})

        return {
            "found": True,
            "ip": ip_address,
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
            "continent": attributes.get("continent"),
            "network": attributes.get("network"),
            "last_analysis_date": datetime.fromtimestamp(
                attributes.get("last_analysis_date", 0)
            ).isoformat() if attributes.get("last_analysis_date") else None,
            "detection_stats": attributes.get("last_analysis_stats", {}),
            "total_detections": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "reputation": attributes.get("reputation"),
            "whois": attributes.get("whois", "")[:1000],
            "source": "virustotal"
        }

    async def get_file_behavior(self, file_hash: str) -> Dict:
        """
        Get sandbox behavior report for a file.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with behavior data
        """
        result = await self._make_request(f"files/{file_hash}/behaviours")

        if "error" in result:
            return result

        data = result.get("data", [])

        behaviors = []
        for behavior in data[:5]:  # Limit to 5 sandbox results
            attrs = behavior.get("attributes", {})
            behaviors.append({
                "sandbox": attrs.get("sandbox_name"),
                "processes": attrs.get("processes_tree", [])[:10],
                "network": {
                    "dns": attrs.get("dns_lookups", [])[:10],
                    "http": attrs.get("http_conversations", [])[:10],
                    "tcp": attrs.get("tcp_connections", [])[:10]
                },
                "files_opened": attrs.get("files_opened", [])[:20],
                "files_written": attrs.get("files_written", [])[:20],
                "registry_keys_set": attrs.get("registry_keys_set", [])[:20],
                "mitre_attack_techniques": attrs.get("mitre_attack_techniques", [])
            })

        return {
            "hash": file_hash,
            "behaviors": behaviors,
            "source": "virustotal"
        }
