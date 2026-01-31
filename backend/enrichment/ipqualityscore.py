"""IPQualityScore API client for malicious URL detection and risk scoring."""

from typing import Dict, Optional


class IPQualityScoreClient:
    """Client for IPQualityScore API."""

    BASE_URL = "https://ipqualityscore.com/api/json"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize IPQualityScore client.

        Args:
            api_key: IPQualityScore API key (free tier: 5000 lookups/month)
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.ipqualityscore_api_key

    async def _make_request(self, endpoint: str, params: Dict = None) -> Dict:
        """Make an API request to IPQualityScore."""
        import httpx

        if not self.api_key:
            return {"error": "IPQualityScore API key not configured"}

        url = f"{self.BASE_URL}/{endpoint}/{self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                if params:
                    response = await client.get(url, params=params)
                else:
                    response = await client.get(url)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("success") is False:
                        return {"error": data.get("message", "API request failed")}
                    return data
                else:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }

        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    async def check_url(self, url: str, strictness: int = 0) -> Dict:
        """
        Check a URL for malicious indicators.

        Args:
            url: URL to check
            strictness: How strict the check should be (0-2)

        Returns:
            Dictionary with risk assessment
        """
        from urllib.parse import quote

        params = {
            "url": url,
            "strictness": strictness,
            "fast": "true"
        }

        # URL needs to be encoded in the path
        encoded_url = quote(url, safe='')
        result = await self._make_request(f"url/{encoded_url}", params)

        if "error" in result:
            return result

        return {
            "url": url,
            "safe": result.get("safe", True),
            "unsafe": result.get("unsafe", False),
            "risk_score": result.get("risk_score", 0),
            "suspicious": result.get("suspicious", False),
            "phishing": result.get("phishing", False),
            "malware": result.get("malware", False),
            "spamming": result.get("spamming", False),
            "adult": result.get("adult", False),
            "category": result.get("category"),
            "domain": result.get("domain"),
            "ip_address": result.get("ip_address"),
            "server": result.get("server"),
            "content_type": result.get("content_type"),
            "status_code": result.get("status_code"),
            "page_size": result.get("page_size"),
            "domain_rank": result.get("domain_rank"),
            "dns_valid": result.get("dns_valid"),
            "parking": result.get("parking"),
            "redirected": result.get("redirected"),
            "final_url": result.get("final_url"),
            "source": "ipqualityscore"
        }

    async def check_ip(self, ip_address: str, strictness: int = 0) -> Dict:
        """
        Check an IP address for fraud/abuse indicators.

        Args:
            ip_address: IP to check
            strictness: How strict the check should be (0-2)

        Returns:
            Dictionary with risk assessment
        """
        params = {
            "ip": ip_address,
            "strictness": strictness,
            "allow_public_access_points": "true"
        }

        result = await self._make_request(f"ip/{ip_address}", params)

        if "error" in result:
            return result

        return {
            "ip": ip_address,
            "fraud_score": result.get("fraud_score", 0),
            "country_code": result.get("country_code"),
            "region": result.get("region"),
            "city": result.get("city"),
            "isp": result.get("ISP"),
            "asn": result.get("ASN"),
            "organization": result.get("organization"),
            "is_crawler": result.get("is_crawler", False),
            "timezone": result.get("timezone"),
            "mobile": result.get("mobile", False),
            "host": result.get("host"),
            "proxy": result.get("proxy", False),
            "vpn": result.get("vpn", False),
            "tor": result.get("tor", False),
            "active_vpn": result.get("active_vpn", False),
            "active_tor": result.get("active_tor", False),
            "recent_abuse": result.get("recent_abuse", False),
            "bot_status": result.get("bot_status", False),
            "connection_type": result.get("connection_type"),
            "abuse_velocity": result.get("abuse_velocity"),
            "source": "ipqualityscore"
        }

    async def check_email(self, email: str, strictness: int = 0) -> Dict:
        """
        Validate an email address for deliverability and fraud.

        Args:
            email: Email address to check
            strictness: How strict the check should be (0-2)

        Returns:
            Dictionary with email validation results
        """
        from urllib.parse import quote

        params = {
            "email": email,
            "strictness": strictness,
            "suggest_domain": "true"
        }

        encoded_email = quote(email, safe='')
        result = await self._make_request(f"email/{encoded_email}", params)

        if "error" in result:
            return result

        return {
            "email": email,
            "valid": result.get("valid", False),
            "disposable": result.get("disposable", False),
            "smtp_score": result.get("smtp_score"),
            "overall_score": result.get("overall_score"),
            "first_name": result.get("first_name"),
            "deliverability": result.get("deliverability"),
            "catch_all": result.get("catch_all", False),
            "generic": result.get("generic", False),
            "common": result.get("common", False),
            "dns_valid": result.get("dns_valid", False),
            "honeypot": result.get("honeypot", False),
            "spam_trap_score": result.get("spam_trap_score"),
            "recent_abuse": result.get("recent_abuse", False),
            "fraud_score": result.get("fraud_score", 0),
            "suspect": result.get("suspect", False),
            "suggested_domain": result.get("suggested_domain"),
            "leaked": result.get("leaked", False),
            "domain_age": result.get("domain_age"),
            "first_seen": result.get("first_seen"),
            "source": "ipqualityscore"
        }

    def interpret_risk_score(self, score: int) -> Dict:
        """
        Interpret a risk score into actionable information.

        Args:
            score: Risk score (0-100)

        Returns:
            Dictionary with interpretation
        """
        if score >= 85:
            return {
                "level": "critical",
                "description": "High risk of malicious activity. Strongly recommend blocking.",
                "action": "block"
            }
        elif score >= 75:
            return {
                "level": "high",
                "description": "Suspicious activity detected. Exercise caution.",
                "action": "review"
            }
        elif score >= 50:
            return {
                "level": "medium",
                "description": "Some risk indicators present. Additional verification recommended.",
                "action": "verify"
            }
        elif score >= 25:
            return {
                "level": "low",
                "description": "Minor risk indicators. Generally safe with monitoring.",
                "action": "monitor"
            }
        else:
            return {
                "level": "minimal",
                "description": "Low risk. No significant concerns detected.",
                "action": "allow"
            }
