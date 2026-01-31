"""CheckPhish API client for URL categorization and phishing detection."""

from typing import Dict, Optional
import asyncio


class CheckPhishClient:
    """Client for CheckPhish API."""

    BASE_URL = "https://developers.checkphish.ai/api"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize CheckPhish client.

        Args:
            api_key: CheckPhish API key
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.checkphish_api_key

    async def scan_url(self, url: str) -> Dict:
        """
        Submit a URL for scanning and get results.

        Args:
            url: URL to scan

        Returns:
            Dictionary with scan results
        """
        import httpx

        if not self.api_key:
            return {"error": "CheckPhish API key not configured"}

        # Submit URL for scanning
        submit_result = await self._submit_scan(url)
        if "error" in submit_result:
            return submit_result

        job_id = submit_result.get("jobID")
        if not job_id:
            return {"error": "No job ID returned from scan submission"}

        # Poll for results
        max_attempts = 10
        for attempt in range(max_attempts):
            await asyncio.sleep(3)  # Wait 3 seconds between polls

            result = await self._get_scan_result(job_id)
            if "error" in result:
                continue

            status = result.get("status")
            if status == "DONE":
                return self._format_result(url, result)
            elif status == "ERROR":
                return {"error": "Scan failed", "detail": result}

        return {"error": "Scan timed out", "job_id": job_id}

    async def _submit_scan(self, url: str) -> Dict:
        """Submit a URL for scanning."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.BASE_URL}/neo/scan",
                    json={
                        "apiKey": self.api_key,
                        "urlInfo": {"url": url},
                        "scanType": "full"
                    }
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def _get_scan_result(self, job_id: str) -> Dict:
        """Get scan results for a job ID."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.BASE_URL}/neo/scan/status",
                    json={
                        "apiKey": self.api_key,
                        "jobID": job_id,
                        "insights": True
                    }
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def _format_result(self, url: str, result: Dict) -> Dict:
        """Format the scan result."""
        return {
            "url": url,
            "job_id": result.get("job_id"),
            "status": result.get("status"),
            "disposition": result.get("disposition"),  # "clean", "phish", "suspicious"
            "brand": result.get("brand"),  # Brand being impersonated if phishing
            "insights": result.get("insights"),
            "categories": result.get("categories", []),
            "resolved_url": result.get("resolved"),
            "screenshot_url": result.get("screenshot_path"),
            "scan_time": result.get("scan_end_ts"),
            "source": "checkphish"
        }

    async def quick_scan(self, url: str) -> Dict:
        """
        Perform a quick scan without waiting for full results.

        Args:
            url: URL to scan

        Returns:
            Dictionary with job ID for later retrieval
        """
        result = await self._submit_scan(url)

        if "error" in result:
            return result

        return {
            "url": url,
            "job_id": result.get("jobID"),
            "status": "submitted",
            "message": "Scan submitted. Use job_id to retrieve results.",
            "source": "checkphish"
        }

    async def get_result(self, job_id: str) -> Dict:
        """
        Get results for a previously submitted scan.

        Args:
            job_id: Job ID from scan submission

        Returns:
            Dictionary with scan results
        """
        result = await self._get_scan_result(job_id)

        if "error" in result:
            return result

        if result.get("status") == "DONE":
            return self._format_result(result.get("url", ""), result)
        else:
            return {
                "job_id": job_id,
                "status": result.get("status"),
                "message": "Scan still in progress",
                "source": "checkphish"
            }
