"""NVD (National Vulnerability Database) API client for CVE enrichment."""

import asyncio
import time
from typing import Dict, List, Optional
from datetime import datetime


class NVDClient:
    """Client for NVD API 2.0 — queries CVE vulnerability data."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (optional — provides higher rate limits)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.nvd_api_key
        self.base_url = settings.nvd_api_url
        # Without key: 5 requests per 30 seconds
        # With key: 50 requests per 30 seconds
        self._min_interval = 6.0 if not self.api_key else 0.6
        self._last_request_time = 0.0

    async def _rate_limit_wait(self):
        """Wait to respect NVD rate limits."""
        now = time.monotonic()
        time_since_last = now - self._last_request_time

        if time_since_last < self._min_interval:
            await asyncio.sleep(self._min_interval - time_since_last)

        self._last_request_time = time.monotonic()

    async def _make_request(self, params: Dict) -> Dict:
        """Make an API request to NVD."""
        import httpx

        await self._rate_limit_wait()

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.base_url, params=params, headers=headers
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 403:
                    return {"error": "Rate limit exceeded or invalid API key", "status_code": 403}
                elif response.status_code == 404:
                    return {"error": "Not found", "status_code": 404}
                else:
                    return {
                        "error": f"NVD API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text[:500]
                    }
        except Exception as e:
            return {"error": f"NVD request failed: {str(e)}"}

    def _parse_cve(self, cve_item: Dict) -> Dict:
        """Parse a CVE item from NVD API response into a normalized dict."""
        cve_data = cve_item.get("cve", {})
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Extract CVSS v3 score
        cvss_v3 = None
        cvss_score = None
        cvss_severity = None
        metrics = cve_data.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                primary = metrics[key][0]
                cvss_data = primary.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_v3 = {
                    "score": cvss_score,
                    "severity": cvss_severity,
                    "vector": cvss_data.get("vectorString"),
                    "attack_vector": cvss_data.get("attackVector"),
                    "attack_complexity": cvss_data.get("attackComplexity"),
                }
                break

        # Extract CWE IDs
        cwes = []
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        # Extract references
        references = []
        for ref in cve_data.get("references", [])[:10]:
            references.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })

        return {
            "cve_id": cve_id,
            "description": description[:1000],
            "cvss_v3": cvss_v3,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cwes": cwes,
            "references": references,
            "published": cve_data.get("published"),
            "last_modified": cve_data.get("lastModified"),
            "source": "nvd"
        }

    async def search_by_keyword(self, keyword: str, results_per_page: int = 10) -> Dict:
        """
        Search for CVEs by keyword.

        Args:
            keyword: Search keyword (software name, vulnerability type, etc.)
            results_per_page: Max results to return (max 100)

        Returns:
            Dictionary with CVE results or error
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 100)
        }

        result = await self._make_request(params)
        if "error" in result:
            return result

        vulnerabilities = result.get("vulnerabilities", [])
        cves = [self._parse_cve(v) for v in vulnerabilities]

        return {
            "found": len(cves) > 0,
            "keyword": keyword,
            "total_results": result.get("totalResults", 0),
            "cves": cves,
            "source": "nvd"
        }

    async def get_cve(self, cve_id: str) -> Dict:
        """
        Look up a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            Dictionary with CVE details or error
        """
        params = {"cveId": cve_id}
        result = await self._make_request(params)
        if "error" in result:
            return result

        vulnerabilities = result.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": "CVE not found", "cve_id": cve_id}

        return self._parse_cve(vulnerabilities[0])

    async def search_by_date_range(self, start: str, end: str,
                                    keyword: Optional[str] = None,
                                    results_per_page: int = 10) -> Dict:
        """
        Search CVEs published within a date range.

        Args:
            start: Start date in ISO format (e.g., "2024-01-01T00:00:00.000")
            end: End date in ISO format
            keyword: Optional keyword filter
            results_per_page: Max results

        Returns:
            Dictionary with CVE results or error
        """
        params = {
            "pubStartDate": start,
            "pubEndDate": end,
            "resultsPerPage": min(results_per_page, 100)
        }
        if keyword:
            params["keywordSearch"] = keyword

        result = await self._make_request(params)
        if "error" in result:
            return result

        vulnerabilities = result.get("vulnerabilities", [])
        cves = [self._parse_cve(v) for v in vulnerabilities]

        return {
            "found": len(cves) > 0,
            "date_range": {"start": start, "end": end},
            "keyword": keyword,
            "total_results": result.get("totalResults", 0),
            "cves": cves,
            "source": "nvd"
        }
