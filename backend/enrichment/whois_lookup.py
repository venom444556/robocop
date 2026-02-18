"""WHOIS lookup client for domain and IP registration data. No API key required."""

import asyncio
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class WhoisLookupClient:
    """Client for WHOIS lookups. No API key or configuration needed."""

    async def lookup_domain(self, domain: str) -> Dict:
        """Look up WHOIS registration data for a domain."""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._sync_domain_lookup, domain)
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    def _sync_domain_lookup(self, domain: str) -> Dict:
        """Synchronous WHOIS lookup for a domain."""
        import whois

        w = whois.whois(domain)

        if not w or not w.domain_name:
            return {"domain": domain, "found": False, "source": "whois"}

        domain_name = w.domain_name
        if isinstance(domain_name, list):
            domain_name = domain_name[0]

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        updated_date = w.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]

        return {
            "domain": domain,
            "found": True,
            "domain_name": str(domain_name) if domain_name else None,
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "updated_date": updated_date.isoformat() if updated_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "org": w.org,
            "country": w.country,
            "state": getattr(w, "state", None),
            "emails": list(w.emails) if w.emails else [],
            "source": "whois",
        }

    async def lookup_ip(self, ip_address: str) -> Dict:
        """Look up WHOIS/RDAP data for an IP address."""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._sync_ip_lookup, ip_address)
        except Exception as e:
            return {"error": f"WHOIS IP lookup failed: {str(e)}"}

    def _sync_ip_lookup(self, ip_address: str) -> Dict:
        """Synchronous RDAP/WHOIS lookup for an IP address."""
        try:
            from ipwhois import IPWhois

            obj = IPWhois(ip_address)
            result = obj.lookup_rdap(depth=1)

            entities = []
            for e in (result.get("objects") or {}).values():
                if isinstance(e, dict):
                    contact = e.get("contact") or {}
                    entities.append({
                        "handle": e.get("handle"),
                        "name": contact.get("name") if isinstance(contact, dict) else None,
                        "roles": e.get("roles", []),
                    })
                if len(entities) >= 5:
                    break

            network = result.get("network") or {}
            return {
                "ip": ip_address,
                "found": True,
                "asn": result.get("asn"),
                "asn_cidr": result.get("asn_cidr"),
                "asn_country_code": result.get("asn_country_code"),
                "asn_description": result.get("asn_description"),
                "asn_date": result.get("asn_date"),
                "network_name": network.get("name"),
                "network_cidr": network.get("cidr"),
                "network_country": network.get("country"),
                "entities": entities,
                "source": "whois",
            }
        except ImportError:
            # Fallback if ipwhois not installed
            try:
                import whois

                w = whois.whois(ip_address)
                return {
                    "ip": ip_address,
                    "found": bool(w and w.domain_name),
                    "registrar": w.registrar if w else None,
                    "org": w.org if w else None,
                    "country": w.country if w else None,
                    "source": "whois",
                }
            except Exception as e:
                return {"error": f"WHOIS fallback failed: {str(e)}"}
