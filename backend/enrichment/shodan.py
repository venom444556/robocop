"""Shodan API client for IP intelligence enrichment."""

from typing import Dict, Optional


class ShodanClient:
    """Client for Shodan API."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan client.

        Args:
            api_key: Shodan API key
        """
        from config import get_settings
        settings = get_settings()
        self.api_key = api_key or settings.shodan_api_key

    async def _make_request(self, endpoint: str, params: Dict = None) -> Dict:
        """Make an API request to Shodan."""
        import httpx

        if not self.api_key:
            return {"error": "Shodan API key not configured"}

        if params is None:
            params = {}
        params["key"] = self.api_key

        url = f"{self.BASE_URL}/{endpoint}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, params=params)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    return {"error": "Not found", "status_code": 404}
                elif response.status_code == 401:
                    return {"error": "Invalid API key", "status_code": 401}
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
        Look up an IP address for open ports, services, and other intelligence.

        Args:
            ip_address: IP address to look up

        Returns:
            Dictionary with Shodan results
        """
        result = await self._make_request(f"shodan/host/{ip_address}")

        if "error" in result:
            # Check if it's just "no results" vs actual error
            if result.get("status_code") == 404:
                return {
                    "found": False,
                    "ip": ip_address,
                    "message": "No data found for this IP",
                    "source": "shodan"
                }
            return result

        # Extract relevant data
        services = []
        for service in result.get("data", []):
            services.append({
                "port": service.get("port"),
                "protocol": service.get("transport", "tcp"),
                "service": service.get("product", service.get("_shodan", {}).get("module")),
                "version": service.get("version"),
                "banner": service.get("data", "")[:500],  # Truncate banner
                "ssl": service.get("ssl", {}).get("cert", {}).get("subject", {}).get("CN") if service.get("ssl") else None,
                "http_title": service.get("http", {}).get("title") if service.get("http") else None
            })

        # Extract vulnerabilities
        vulns = []
        for vuln in result.get("vulns", []):
            vulns.append(vuln)

        return {
            "found": True,
            "ip": ip_address,
            "hostnames": result.get("hostnames", []),
            "domains": result.get("domains", []),
            "country": result.get("country_name"),
            "country_code": result.get("country_code"),
            "city": result.get("city"),
            "region": result.get("region_code"),
            "org": result.get("org"),
            "asn": result.get("asn"),
            "isp": result.get("isp"),
            "os": result.get("os"),
            "ports": result.get("ports", []),
            "services": services,
            "vulnerabilities": vulns,
            "tags": result.get("tags", []),
            "last_update": result.get("last_update"),
            "source": "shodan"
        }

    async def lookup_domain(self, domain: str) -> Dict:
        """
        Look up DNS information for a domain.

        Args:
            domain: Domain to look up

        Returns:
            Dictionary with DNS data
        """
        result = await self._make_request(f"dns/domain/{domain}")

        if "error" in result:
            return result

        return {
            "found": True,
            "domain": domain,
            "subdomains": result.get("subdomains", [])[:50],
            "dns_records": result.get("data", []),
            "tags": result.get("tags", []),
            "source": "shodan"
        }

    async def reverse_dns(self, ip_address: str) -> Dict:
        """
        Get reverse DNS for an IP address.

        Args:
            ip_address: IP to look up

        Returns:
            Dictionary with reverse DNS data
        """
        result = await self._make_request("dns/reverse", params={"ips": ip_address})

        if "error" in result:
            return result

        hostnames = result.get(ip_address, [])

        return {
            "ip": ip_address,
            "hostnames": hostnames,
            "source": "shodan"
        }

    async def search_exploits(self, query: str) -> Dict:
        """
        Search for exploits related to a query (e.g., CVE, product name).

        Args:
            query: Search query

        Returns:
            Dictionary with exploit data
        """
        result = await self._make_request("api-ms/exploits/search", params={"query": query})

        if "error" in result:
            return result

        exploits = []
        for exploit in result.get("matches", [])[:20]:
            exploits.append({
                "id": exploit.get("_id"),
                "description": exploit.get("description", "")[:500],
                "type": exploit.get("type"),
                "platform": exploit.get("platform"),
                "port": exploit.get("port"),
                "source": exploit.get("source"),
                "cve": exploit.get("cve", [])
            })

        return {
            "query": query,
            "total": result.get("total", 0),
            "exploits": exploits,
            "source": "shodan"
        }

    async def get_api_info(self) -> Dict:
        """
        Get information about the API plan and usage.

        Returns:
            Dictionary with API info
        """
        result = await self._make_request("api-info")

        if "error" in result:
            return result

        return {
            "plan": result.get("plan"),
            "query_credits": result.get("query_credits"),
            "scan_credits": result.get("scan_credits"),
            "monitored_ips": result.get("monitored_ips"),
            "source": "shodan"
        }
