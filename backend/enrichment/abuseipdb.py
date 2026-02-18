"""AbuseIPDB API client for IP abuse reputation scoring."""

from typing import Dict, Optional


class AbuseIPDBClient:
    """Client for AbuseIPDB API (free: 1,000 checks/day)."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key (free tier: 1,000 checks/day)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.abuseipdb_api_key

    async def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict:
        """
        Check an IP address for abuse reports.

        Args:
            ip_address: IP address to check
            max_age_days: How far back to look for reports (1-365)

        Returns:
            Dictionary with abuse data
        """
        import httpx

        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": str(max_age_days),
            "verbose": ""
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params=params
                )

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    return self._format_response(ip_address, data)
                elif response.status_code == 429:
                    return {"error": "AbuseIPDB rate limit exceeded (1,000/day free tier)"}
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def _format_response(self, ip_address: str, data: Dict) -> Dict:
        """Format the AbuseIPDB API response."""
        return {
            "ip": ip_address,
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "is_public": data.get("isPublic", True),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "hostnames": data.get("hostnames", []),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "source": "abuseipdb"
        }

    async def get_blacklist(self, confidence_minimum: int = 90, limit: int = 100) -> Dict:
        """
        Get the AbuseIPDB blacklist.

        Args:
            confidence_minimum: Minimum abuse confidence score (1-100)
            limit: Max results (free: 10,000)

        Returns:
            Dictionary with blacklisted IPs
        """
        import httpx

        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "confidenceMinimum": str(confidence_minimum),
            "limit": str(min(limit, 10000))
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/blacklist",
                    headers=headers,
                    params=params
                )

                if response.status_code == 200:
                    data = response.json().get("data", [])
                    return {
                        "count": len(data),
                        "confidence_minimum": confidence_minimum,
                        "ips": [
                            {
                                "ip": entry.get("ipAddress"),
                                "abuse_confidence_score": entry.get("abuseConfidenceScore"),
                                "last_reported_at": entry.get("lastReportedAt")
                            }
                            for entry in data[:limit]
                        ],
                        "source": "abuseipdb"
                    }
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    def interpret_abuse_score(self, score: int) -> Dict:
        """
        Interpret an AbuseIPDB confidence score.

        Args:
            score: Abuse confidence score (0-100)

        Returns:
            Dictionary with interpretation
        """
        if score >= 80:
            return {
                "level": "critical",
                "description": "Strong community consensus of abuse. Recommend immediate block.",
                "action": "block"
            }
        elif score >= 50:
            return {
                "level": "high",
                "description": "Multiple abuse reports. Exercise caution.",
                "action": "review"
            }
        elif score >= 25:
            return {
                "level": "medium",
                "description": "Some abuse reports. Monitor for suspicious activity.",
                "action": "monitor"
            }
        elif score > 0:
            return {
                "level": "low",
                "description": "Few abuse reports. Likely low risk.",
                "action": "monitor"
            }
        else:
            return {
                "level": "clean",
                "description": "No abuse reports found.",
                "action": "allow"
            }
