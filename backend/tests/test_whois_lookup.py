"""Tests for WHOIS lookup enrichment client."""

from unittest.mock import patch, MagicMock
from datetime import datetime
import pytest

from enrichment.whois_lookup import WhoisLookupClient


class TestLookupDomain:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_whois = MagicMock()
        mock_whois.domain_name = "example.com"
        mock_whois.registrar = "Example Registrar Inc."
        mock_whois.creation_date = datetime(2020, 1, 15)
        mock_whois.expiration_date = datetime(2025, 1, 15)
        mock_whois.updated_date = datetime(2024, 6, 1)
        mock_whois.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_whois.org = "Example Corp"
        mock_whois.country = "US"
        mock_whois.state = "CA"
        mock_whois.emails = ["admin@example.com"]

        with patch("enrichment.whois_lookup.WhoisLookupClient._sync_domain_lookup", return_value={
            "domain": "example.com",
            "found": True,
            "registrar": "Example Registrar Inc.",
            "creation_date": "2020-01-15T00:00:00",
            "expiration_date": "2025-01-15T00:00:00",
            "org": "Example Corp",
            "country": "US",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "source": "whois",
        }):
            c = WhoisLookupClient()
            result = await c.lookup_domain("example.com")
            assert result["found"] is True
            assert result["registrar"] == "Example Registrar Inc."
            assert result["source"] == "whois"

    @pytest.mark.asyncio
    async def test_domain_not_found(self):
        with patch("enrichment.whois_lookup.WhoisLookupClient._sync_domain_lookup", return_value={
            "domain": "nonexistent12345.xyz",
            "found": False,
            "source": "whois",
        }):
            c = WhoisLookupClient()
            result = await c.lookup_domain("nonexistent12345.xyz")
            assert result["found"] is False

    @pytest.mark.asyncio
    async def test_lookup_exception(self):
        with patch("enrichment.whois_lookup.WhoisLookupClient._sync_domain_lookup",
                    side_effect=Exception("WHOIS server timeout")):
            c = WhoisLookupClient()
            result = await c.lookup_domain("example.com")
            assert "error" in result

    def test_sync_domain_lookup_success(self):
        mock_whois_result = MagicMock()
        mock_whois_result.domain_name = "example.com"
        mock_whois_result.registrar = "GoDaddy"
        mock_whois_result.creation_date = datetime(2020, 1, 1)
        mock_whois_result.expiration_date = datetime(2026, 1, 1)
        mock_whois_result.updated_date = datetime(2024, 6, 1)
        mock_whois_result.name_servers = ["ns1.example.com"]
        mock_whois_result.org = "Test Org"
        mock_whois_result.country = "US"
        mock_whois_result.state = "NY"
        mock_whois_result.emails = ["abuse@example.com"]

        with patch("whois.whois", return_value=mock_whois_result):
            c = WhoisLookupClient()
            result = c._sync_domain_lookup("example.com")
            assert result["found"] is True
            assert result["registrar"] == "GoDaddy"
            assert result["org"] == "Test Org"

    def test_sync_domain_lookup_not_found(self):
        mock_whois_result = MagicMock()
        mock_whois_result.domain_name = None

        with patch("whois.whois", return_value=mock_whois_result):
            c = WhoisLookupClient()
            result = c._sync_domain_lookup("nonexistent.xyz")
            assert result["found"] is False


class TestLookupIP:
    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        with patch("enrichment.whois_lookup.WhoisLookupClient._sync_ip_lookup", return_value={
            "ip": "8.8.8.8",
            "found": True,
            "asn": "AS15169",
            "asn_description": "GOOGLE",
            "asn_country_code": "US",
            "network_name": "GOOGLE",
            "source": "whois",
        }):
            c = WhoisLookupClient()
            result = await c.lookup_ip("8.8.8.8")
            assert result["found"] is True
            assert result["asn"] == "AS15169"
            assert result["source"] == "whois"

    @pytest.mark.asyncio
    async def test_lookup_exception(self):
        with patch("enrichment.whois_lookup.WhoisLookupClient._sync_ip_lookup",
                    side_effect=Exception("Connection refused")):
            c = WhoisLookupClient()
            result = await c.lookup_ip("8.8.8.8")
            assert "error" in result

    def test_sync_ip_lookup_with_ipwhois(self):
        mock_result = {
            "asn": "15169",
            "asn_cidr": "8.8.8.0/24",
            "asn_country_code": "US",
            "asn_description": "GOOGLE",
            "asn_date": "2014-03-14",
            "network": {"name": "LVLT-GOGL-8-8-8", "cidr": "8.8.8.0/24", "country": "US"},
            "objects": {
                "GOGL": {"handle": "GOGL", "contact": {"name": "Google LLC"}, "roles": ["registrant"]}
            }
        }

        mock_ipwhois = MagicMock()
        mock_ipwhois.return_value.lookup_rdap.return_value = mock_result

        with patch.dict("sys.modules", {"ipwhois": MagicMock(IPWhois=mock_ipwhois)}):
            # Need to reimport to pick up the mock
            from enrichment.whois_lookup import WhoisLookupClient as WLC
            c = WLC()
            result = c._sync_ip_lookup("8.8.8.8")
            assert result["found"] is True
            assert result["asn"] == "15169"
