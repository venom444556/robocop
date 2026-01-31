"""URLhaus API client for malware URL database lookups."""

from typing import Dict, Optional


class URLhausClient:
    """Client for URLhaus API (abuse.ch)."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, auth_key: Optional[str] = None):
        """
        Initialize URLhaus client.

        Args:
            auth_key: URLhaus Auth-Key (optional, for higher rate limits)
        """
        from config import get_settings
        settings = get_settings()
        self.auth_key = auth_key or settings.urlhaus_auth_key

    async def _make_request(self, endpoint: str, data: Dict) -> Dict:
        """Make an API request to URLhaus."""
        import httpx

        url = f"{self.BASE_URL}/{endpoint}/"

        headers = {}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, data=data, headers=headers)

                if response.status_code == 200:
                    return response.json()
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def lookup_url(self, url: str) -> Dict:
        """
        Look up a URL in the URLhaus database.

        Args:
            url: URL to look up

        Returns:
            Dictionary with URLhaus results
        """
        result = await self._make_request("url", {"url": url})

        if "error" in result:
            return result

        if result.get("query_status") == "no_results":
            return {
                "found": False,
                "url": url,
                "message": "URL not found in URLhaus database",
                "source": "urlhaus"
            }

        return {
            "found": True,
            "url": url,
            "url_id": result.get("id"),
            "url_status": result.get("url_status"),
            "host": result.get("host"),
            "date_added": result.get("date_added"),
            "threat": result.get("threat"),
            "blacklists": result.get("blacklists", {}),
            "reporter": result.get("reporter"),
            "larted": result.get("larted"),
            "tags": result.get("tags", []),
            "payloads": self._format_payloads(result.get("payloads", [])),
            "source": "urlhaus"
        }

    def _format_payloads(self, payloads: list) -> list:
        """Format payload data from URLhaus."""
        formatted = []
        for payload in payloads[:10]:  # Limit to 10 payloads
            formatted.append({
                "filename": payload.get("filename"),
                "file_type": payload.get("file_type"),
                "md5": payload.get("response_md5"),
                "sha256": payload.get("response_sha256"),
                "signature": payload.get("signature"),
                "first_seen": payload.get("firstseen"),
                "vt_detection": payload.get("virustotal", {}).get("percent")
            })
        return formatted

    async def lookup_host(self, host: str) -> Dict:
        """
        Look up a host (domain or IP) in URLhaus.

        Args:
            host: Host to look up

        Returns:
            Dictionary with URLhaus results
        """
        result = await self._make_request("host", {"host": host})

        if "error" in result:
            return result

        if result.get("query_status") == "no_results":
            return {
                "found": False,
                "host": host,
                "message": "Host not found in URLhaus database",
                "source": "urlhaus"
            }

        # Format URLs associated with host
        urls = []
        for url_entry in result.get("urls", [])[:20]:
            urls.append({
                "url": url_entry.get("url"),
                "url_status": url_entry.get("url_status"),
                "date_added": url_entry.get("date_added"),
                "threat": url_entry.get("threat"),
                "tags": url_entry.get("tags", [])
            })

        return {
            "found": True,
            "host": host,
            "firstseen": result.get("firstseen"),
            "url_count": result.get("url_count"),
            "blacklists": result.get("blacklists", {}),
            "urls": urls,
            "source": "urlhaus"
        }

    async def lookup_hash(self, file_hash: str, hash_type: str = "sha256") -> Dict:
        """
        Look up a file hash (payload) in URLhaus.

        Args:
            file_hash: Hash to look up
            hash_type: Type of hash (md5 or sha256)

        Returns:
            Dictionary with URLhaus results
        """
        data = {f"{hash_type}_hash": file_hash}
        result = await self._make_request("payload", data)

        if "error" in result:
            return result

        if result.get("query_status") == "no_results":
            return {
                "found": False,
                "hash": file_hash,
                "hash_type": hash_type,
                "message": "Hash not found in URLhaus database",
                "source": "urlhaus"
            }

        # Format URLs serving this payload
        urls = []
        for url_entry in result.get("urls", [])[:20]:
            urls.append({
                "url": url_entry.get("url"),
                "url_status": url_entry.get("url_status"),
                "filename": url_entry.get("filename"),
                "first_seen": url_entry.get("firstseen")
            })

        return {
            "found": True,
            "hash": file_hash,
            "hash_type": hash_type,
            "md5": result.get("md5_hash"),
            "sha256": result.get("sha256_hash"),
            "file_type": result.get("file_type"),
            "file_size": result.get("file_size"),
            "signature": result.get("signature"),
            "first_seen": result.get("firstseen"),
            "last_seen": result.get("lastseen"),
            "url_count": result.get("url_count"),
            "vt_detection": result.get("virustotal", {}).get("percent"),
            "imphash": result.get("imphash"),
            "ssdeep": result.get("ssdeep"),
            "tlsh": result.get("tlsh"),
            "urls": urls,
            "source": "urlhaus"
        }

    async def lookup_tag(self, tag: str) -> Dict:
        """
        Look up URLs by tag (e.g., "emotet", "cobalt_strike").

        Args:
            tag: Tag to search for

        Returns:
            Dictionary with matching URLs
        """
        result = await self._make_request("tag", {"tag": tag})

        if "error" in result:
            return result

        if result.get("query_status") == "no_results":
            return {
                "found": False,
                "tag": tag,
                "message": f"No URLs found with tag: {tag}",
                "source": "urlhaus"
            }

        urls = []
        for url_entry in result.get("urls", [])[:50]:
            urls.append({
                "url": url_entry.get("url"),
                "url_status": url_entry.get("url_status"),
                "host": url_entry.get("host"),
                "date_added": url_entry.get("date_added"),
                "threat": url_entry.get("threat"),
                "tags": url_entry.get("tags", [])
            })

        return {
            "found": True,
            "tag": tag,
            "url_count": len(urls),
            "urls": urls,
            "source": "urlhaus"
        }

    async def lookup_signature(self, signature: str) -> Dict:
        """
        Look up payloads by malware signature.

        Args:
            signature: Malware signature/family name

        Returns:
            Dictionary with matching payloads
        """
        result = await self._make_request("signature", {"signature": signature})

        if "error" in result:
            return result

        if result.get("query_status") == "no_results":
            return {
                "found": False,
                "signature": signature,
                "message": f"No payloads found with signature: {signature}",
                "source": "urlhaus"
            }

        payloads = []
        for payload in result.get("payloads", [])[:50]:
            payloads.append({
                "md5": payload.get("md5_hash"),
                "sha256": payload.get("sha256_hash"),
                "file_type": payload.get("file_type"),
                "file_size": payload.get("file_size"),
                "first_seen": payload.get("firstseen"),
                "url_count": payload.get("url_count"),
                "vt_detection": payload.get("virustotal", {}).get("percent")
            })

        return {
            "found": True,
            "signature": signature,
            "payload_count": len(payloads),
            "payloads": payloads,
            "source": "urlhaus"
        }

    async def get_recent_urls(self, limit: int = 100) -> Dict:
        """
        Get recently added malicious URLs.

        Args:
            limit: Number of URLs to retrieve (max 1000)

        Returns:
            Dictionary with recent URLs
        """
        result = await self._make_request("urls/recent", {"limit": min(limit, 1000)})

        if "error" in result:
            return result

        urls = []
        for url_entry in result.get("urls", []):
            urls.append({
                "url": url_entry.get("url"),
                "url_status": url_entry.get("url_status"),
                "host": url_entry.get("host"),
                "date_added": url_entry.get("date_added"),
                "threat": url_entry.get("threat"),
                "tags": url_entry.get("tags", [])
            })

        return {
            "url_count": len(urls),
            "urls": urls,
            "source": "urlhaus"
        }
