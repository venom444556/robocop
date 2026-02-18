"""urlscan.io API client for URL analysis and intelligence."""

import asyncio
from typing import Dict, Optional


class URLScanClient:
    """Client for urlscan.io API (free: 50 private + 5,000 public scans/day)."""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize urlscan.io client.

        Args:
            api_key: urlscan.io API key (free account required)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.urlscan_api_key

    async def scan_url(self, url: str, visibility: str = "public") -> Dict:
        """
        Submit a URL for scanning and wait for results.

        Args:
            url: URL to scan
            visibility: Scan visibility ("public", "unlisted", or "private")

        Returns:
            Dictionary with scan results
        """
        import httpx

        if not self.api_key:
            return {"error": "urlscan.io API key not configured"}

        headers = {
            "Content-Type": "application/json",
            "API-Key": self.api_key
        }
        body = {
            "url": url,
            "visibility": visibility
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Submit scan
                response = await client.post(
                    f"{self.BASE_URL}/scan/",
                    headers=headers,
                    json=body
                )

                if response.status_code == 200:
                    submit_data = response.json()
                    result_uuid = submit_data.get("uuid")
                    if not result_uuid:
                        return {"error": "No scan UUID returned"}

                    # Poll for results (urlscan takes 10-30s)
                    return await self._poll_result(result_uuid, url)
                elif response.status_code == 429:
                    return {"error": "urlscan.io rate limit exceeded"}
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def _poll_result(self, uuid: str, original_url: str,
                           max_wait: int = 60, interval: int = 5) -> Dict:
        """Poll for scan results."""
        import httpx

        for _ in range(max_wait // interval):
            await asyncio.sleep(interval)
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(f"{self.BASE_URL}/result/{uuid}/")

                    if response.status_code == 200:
                        data = response.json()
                        return self._format_result(original_url, uuid, data)
                    elif response.status_code == 404:
                        continue  # Not ready yet
                    else:
                        return {
                            "error": f"Result poll error: {response.status_code}",
                            "uuid": uuid
                        }
            except Exception:
                continue

        return {
            "url": original_url,
            "uuid": uuid,
            "status": "pending",
            "message": "Scan still processing. Check results later.",
            "result_url": f"https://urlscan.io/result/{uuid}/",
            "source": "urlscan"
        }

    def _format_result(self, original_url: str, uuid: str, data: Dict) -> Dict:
        """Format urlscan.io result data."""
        page = data.get("page", {})
        lists = data.get("lists", {})
        stats = data.get("stats", {})
        verdicts = data.get("verdicts", {})
        overall = verdicts.get("overall", {})

        return {
            "url": original_url,
            "uuid": uuid,
            "result_url": f"https://urlscan.io/result/{uuid}/",
            "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
            "effective_url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "server": page.get("server"),
            "status_code": page.get("status"),
            "title": page.get("title"),
            "mime_type": page.get("mimeType"),
            "malicious": overall.get("malicious", False),
            "score": overall.get("score", 0),
            "categories": overall.get("categories", []),
            "tags": overall.get("tags", []),
            "brands": overall.get("brands", []),
            "unique_ips": stats.get("uniqIPs"),
            "unique_countries": stats.get("uniqCountries"),
            "total_links": stats.get("totalLinks"),
            "urls_contacted": len(lists.get("urls", []))[:20] if lists.get("urls") else 0,
            "ips_contacted": lists.get("ips", [])[:20],
            "domains_contacted": lists.get("domains", [])[:20],
            "certificates": [
                c.get("subjectName") for c in lists.get("certificates", [])[:10]
            ],
            "source": "urlscan"
        }

    async def search(self, query: str, size: int = 10) -> Dict:
        """
        Search urlscan.io for existing scans.

        Args:
            query: Search query (e.g., "domain:example.com" or "ip:1.2.3.4")
            size: Number of results (max 100)

        Returns:
            Dictionary with search results
        """
        import httpx

        headers = {}
        if self.api_key:
            headers["API-Key"] = self.api_key

        params = {
            "q": query,
            "size": str(min(size, 100))
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/search/",
                    headers=headers,
                    params=params
                )

                if response.status_code == 200:
                    data = response.json()
                    results = []
                    for r in data.get("results", [])[:size]:
                        page = r.get("page", {})
                        task = r.get("task", {})
                        results.append({
                            "uuid": task.get("uuid"),
                            "url": task.get("url"),
                            "domain": page.get("domain"),
                            "ip": page.get("ip"),
                            "country": page.get("country"),
                            "server": page.get("server"),
                            "title": page.get("title"),
                            "status": page.get("status"),
                            "scanned_at": task.get("time")
                        })
                    return {
                        "query": query,
                        "total": data.get("total", 0),
                        "results": results,
                        "source": "urlscan"
                    }
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def lookup_domain(self, domain: str) -> Dict:
        """
        Search for existing scans of a domain.

        Args:
            domain: Domain to search for

        Returns:
            Dictionary with domain scan history
        """
        return await self.search(f"domain:{domain}", size=10)

    async def lookup_ip(self, ip_address: str) -> Dict:
        """
        Search for existing scans involving an IP.

        Args:
            ip_address: IP to search for

        Returns:
            Dictionary with IP scan history
        """
        return await self.search(f"ip:{ip_address}", size=10)
